# udpmimic

**[English](README.md) | 简体中文**

把 UDP 流量伪装成普通 TCP，用来穿过只放行/优待 TCP 的防火墙和 QoS。
这是 [`udp2raw`](https://github.com/wangyu-/udp2raw) fake-tcp 模式的
极简、无第三方依赖重实现：不加密、不鉴权、不做防重放、不做花哨的反指纹——
只做伪装本身，专注跑得快。

- **仅 Linux**，单线程 epoll + raw socket，不依赖 libev/uthash/libpcap，
  只用 libc。
- **IPv4 + IPv6**，包括双栈（`[::]` 同一端口同时接受两种）。
- **一对多客户端**。服务端会话查找 O(1)（哈希表 + 对象池，热路径零堆
  分配），空闲会话淘汰用 LRU 链表做到均摊 O(1)，不是全表扫描。
- **一对多本地应用**。单个 client 进程可以同时给多个不同的本地 UDP
  应用转发，每个各自一条独立的伪装 TCP“连接”。
- raw socket 上挂了一个经典 BPF 过滤器，让内核在报文进入用户态之前
  就按端口丢掉无关的 TCP 流量——否则一个 `IPPROTO_TCP` raw socket
  会收到主机上*所有*的 TCP 包。

线上协议格式、会话管理设计、以及哪些东西被有意砍掉（和为什么）见
[DESIGN.md](DESIGN.md)（英文）。

## 编译

```bash
make
```

纯 C，无第三方依赖。产物是单个 `udpmimic` 二进制，靠 `-s`/`-c` 切换
角色，scp 到第二台机器只需要这一个文件。

## 用法

服务端（跑在客户端能访问到的地方，转发到真实 UDP 服务，比如
OpenVPN/WireGuard 服务端）：

```bash
./udpmimic -s -l 0.0.0.0:4096 -r 127.0.0.1:1194 [-n 4096] [-t 120] [-v]
```

客户端（跑在你的 UDP 应用所在的机器，应用照常连本地 UDP 端口，底层
流量被伪装成 TCP）：

```bash
./udpmimic -c -l 127.0.0.1:1195 -r <server_ip>:4096 [-n 256] [-k 20] [-v]
```

需要 root 或 `CAP_NET_RAW`（raw socket 收发）。地址格式：IPv4 用
`ip:port`，IPv6 用 `[ip6]:port`——比如 `-l [::]:8390` 会同时监听 IPv6
*和* 在同一端口接受 IPv4 客户端（双栈）。

| 参数 | 含义 | 默认值 |
|---|---|---|
| `-s` / `-c` | 服务端 / 客户端模式 | 必填 |
| `-l ip:port` | 服务端：伪装监听地址；客户端：本地 UDP 绑定地址 | 必填 |
| `-r ip:port` | 服务端：真实 UDP 后端；客户端：udpmimic 服务端地址 | 必填 |
| `-n N` | 最大并发会话数（服务端=客户端数；客户端=本地应用数） | 4096 / 256 |
| `-t sec` | 会话空闲超时 | 120 |
| `-k sec` | 客户端 keepalive 间隔 | 20 |
| `-v` | 输出调试日志 | 关闭 |

## 必须加的防火墙规则

本机真实的 TCP/IP 协议栈也会看到一份伪装包的拷贝，但因为背后没有真正
的 socket，会尝试回一个 RST。放任不管的话这个 RST 会破坏伪装。只丢
内核自己发出的 RST（不影响其它任何流量）：

```bash
# 服务端上，PORT 换成你 -l 用的端口
iptables  -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP
ip6tables -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP   # 如果用 IPv6

# 客户端上，PORT 换成服务端的端口
iptables  -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
ip6tables -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
```

按你发行版平时持久化 iptables 规则的方式处理即可——udpmimic 本身不会
代为修改防火墙规则。

## 已知限制

- 按设计不加密、不鉴权——把它单纯当作一层伪装，不要当成安全边界。
- 客户端会话是按外层 `(ip, port)` 识别的；如果这个四元组中途变了
  （比如客户端 NAT 重新映射），旧会话会直接超时，新会话重新握手——
  没有 `udp2raw` 那种 conv_id 连接延续机制。
- 如果主机上有严格的 conntrack 加固规则（`-m conntrack --ctstate
  INVALID -j DROP`），流量可能仍会被丢弃，与上面那条规则无关；遇到
  这种情况可以在 `raw` 表里加一条 `NOTRACK` 规则试试。

## CI

`.github/workflows/release.yml` 每次 push 都会交叉编译
x86_64/aarch64/armv7/armv5/mips/mipsel 的静态 musl 二进制，打 tag 时
自动发布到 GitHub Releases——方便直接扔到路由器/嵌入式设备上跑。
