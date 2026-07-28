# udpmimic

把 UDP 流量伪装成 TCP（fake-tcp），用于穿越只放行/优待 TCP 的防火墙 /
QoS。功能对标 `udp2raw` 的 fake-tcp 模式，但去掉加密、鉴权、防重放，
只用 Linux epoll + raw socket 实现，追求极简和高效。详细设计见
[DESIGN.md](DESIGN.md)。

**不做**：加密、身份鉴权、IPv6、多线程扩展、除 fake-tcp 外的其它伪装
模式。这些都不是本工具的目标。

## 编译

```bash
make
```

只依赖 libc，产物是单个二进制 `udpmimic`，靠 `-s`/`-c` 切换服务端/
客户端角色，方便直接 scp 到远端机器。

## 用法

服务端（跑在能被客户端访问到的公网机器上，转发到本机/内网的真实
UDP 服务，比如 OpenVPN/WireGuard 服务端）：

```bash
./udpmimic -s -l 0.0.0.0:4096 -r 127.0.0.1:1194 [-n 4096] [-t 120] [-v]
```

客户端（跑在你自己的机器上，本地 UDP 应用照常连本地端口，实际流量
经这里伪装成 TCP 发给服务端）：

```bash
./udpmimic -c -l 127.0.0.1:1195 -r <server_ip>:4096 [-n 256] [-k 20] [-v]
```

### 参数

| 参数 | 含义 | 默认 |
|---|---|---|
| `-s` / `-c` | 服务端 / 客户端模式 | 必填其一 |
| `-l ip:port` | 服务端：伪装 TCP 监听地址；客户端：本地 UDP 绑定地址 | 必填 |
| `-r ip:port` | 服务端：真实 UDP 后端地址；客户端：udpmimic 服务端地址 | 必填 |
| `-n N` | 最大并发会话数（服务端=最大客户端数，客户端=最大本地应用数） | 服务端 4096 / 客户端 256 |
| `-t sec` | 会话空闲超时后回收 | 120 |
| `-k sec` | 客户端 keepalive 间隔 | 20 |
| `-v` | 输出调试日志 | 关闭 |

客户端的 `-l` 只需要绑定一次：本地有几个不同的 UDP 应用/端口连过来，
客户端会自动按来源地址各开一条独立的伪装 TCP 连接转发给服务端，
不需要为每个本地应用单独起一份 udpmimic 进程。

需要 root 或 `CAP_NET_RAW`（raw socket 收发伪装包必须）。

## 必须配置的 iptables 规则

本机真实的 TCP/IP 协议栈也会看到一份这些伪装包的拷贝，但因为本机
并没有真正 `listen()`/`connect()` 那个四元组，内核会认为是非法 TCP
段并企图回一个 RST——这个 RST 一旦真被发出去会打断伪装。解决方式是
**只丢内核自己生成的出站 RST**，不要在 INPUT 链丢包（那样 raw socket
自己也收不到包了）：

```bash
# 服务端上，PORT 换成 -l 里配的伪装监听端口
iptables -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP

# 客户端上，PORT 换成 -r 里服务端的端口
iptables -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
```

这两条规则只影响 RST，不影响本机其它正常 TCP 连接。如果需要重启后
仍然生效，按发行版自行持久化（`iptables-save`、`netfilter-persistent`
之类），udpmimic 本身不会替你修改防火墙规则。

## 测试

### 单机自环

```bash
make
# 模拟真实 UDP 后端
ncat -u -l 127.0.0.1 1194 -k -c 'cat' &
./udpmimic -s -l 127.0.0.1:4096 -r 127.0.0.1:1194 -v &
./udpmimic -c -l 127.0.0.1:1195 -r 127.0.0.1:4096 -v &
echo hello | ncat -u 127.0.0.1 1195
```

用 `tcpdump -i lo tcp port 4096` 能看到握手 + PSH+ACK 数据包。

### 双机测试

```bash
scp -P 1822 udpmimic root@72.18.81.227:/root/
```

一端跑 `-s`，另一端跑 `-c`，中间用真实网络验证：

1. 三次握手能否正常建立，`tcpdump -i any tcp port <PORT>` 抓包确认
   报文形态；
2. 数据双向转发是否正常（可以直接接一个真实的 OpenVPN/WireGuard
   隧道做端到端验证）；
3. 不加上面的 iptables 规则时，观察是否出现内核自动 RST 导致连接
   异常；加上规则后确认问题消失；
4. 多个客户端 session 并发、以及单个 client 进程同时给多个本地 UDP
   应用转发时，服务端/客户端的会话表是否正确区分、超时后正确回收。
