# udpmimic 设计文档

## 0. 目标与范围

功能对标 `udp2raw` 的 **fake-tcp** 模式（把 UDP 流量伪装成看起来正常的 TCP
握手+数据流，绕过对 UDP 限速/封锁的防火墙/QoS），但主动砍掉以下内容以换取
极致精简和效率：

- 不做加密、不做 HMAC 鉴权、不做防重放（用户明确不需要）
- 只支持 fake-tcp 一种伪装模式（不做 icmp/udp 伪装模式）
- 只支持 Linux + epoll，只用 libc，不引入 libev/uthash 等依赖
- 只支持 IPv4（IPv6 不在 v1 范围内，接口预留）

保留、且是重点的部分：

- server 端一对多客户端会话的高效管理（借鉴 shadowsocks-libev 的思路，
  但去掉 uthash/ev_tstamp 依赖，手写更贴合本场景的哈希表 + O(1) LRU 淘汰）
- 收发路径零堆分配（栈缓冲区 + 会话对象池）
- epoll 边缘触发、非阻塞、kernel 风格代码（Linux kernel coding style：
  goto 错误处理、intrusive list、紧凑命名）

## 1. 拓扑

```
N 个本地 UDP 应用                                       真实 UDP 后端(单一地址)
(如多个 OpenVPN/WireGuard 客户端进程)                    (如 OpenVPN/WireGuard 服务端)
      |  UDP (同一个本地 socket, 不同 peer)                     ^  UDP (每 session 独立 fd)
      v                                                          |
  [udpmimic -c 客户端]  == N 条独立的伪装 TCP "连接" ==>  [udpmimic -s 服务端]
   本地 UDP socket (1个,           raw socket (1个,        raw socket (1个)   N 个 UDP socket
   recvfrom/sendto 区分 peer)   每 session 用不同的       按 (src_ip,        (每 session 一个,
                                 outer TCP 源端口区分)     src_port) 区分)     connect() 到后端)
```

- **client 进程**：对接**一个**远端 server，但可以同时对接**多个**本地
  UDP 应用（同一台机器上多个不同 UDP 端口的进程，比如同时给几个不同的
  本地服务包一层）。做法是让每个"本地 UDP 对端"对应一条**独立的**
  伪装 TCP 连接（各自独立的 outer TCP 源端口 + 独立 seq/ack 状态），
  而不是在一条连接里做二次复用协议——这样完全复用 server 端本来就要做的
  "多会话哈希表"机制，不需要再发明一层内部分帧协议。
- **server 进程**：一个 raw socket 接收所有伪装 TCP 包，按
  `(src_ip,src_port)` 区分出 N 个会话（不区分这个远端是不同物理机器的
  客户端，还是同一个 client 进程为不同本地应用开的多条连接，server 视角
  完全一致），每个会话对应一个独立 `connect()` 到同一个后端 UDP 地址的
  UDP socket。

## 2. 协议设计（线上格式）

不用真实内核 TCP 协议栈跑握手/重传，只是**手工拼出**看起来合法的
IPv4+TCP 头，載荷即原始 UDP payload（不加长度前缀 —— 我们自己收发
每个 raw 包对应一个完整 UDP 数据报，不依赖内核 TCP 的流重组，所以
1 个 IP 包 = 1 个 UDP 数据报，无需额外分帧）。

字段策略：

- IP 头：手工构造（`IP_HDRINCL`），ttl/id 随意但需自算 checksum。
- TCP 头：sport/dport 固定（客户端 sport 随机一次性选定，server 端
  dport 就是监听端口），seq/ack 仅用于让报文在防火墙深度检测下
  看起来像正常递增的 TCP 流，**不做真正的重传/乱序重组**——丢包语义
  与 UDP 完全一致（这是简化的核心：因为底层就是 UDP，不需要 TCP 的
  可靠性）。
- 握手：SYN → SYN+ACK → ACK 三次握手过后才进入 ESTABLISHED、才允许
  转发数据，server 在收到 SYN 时创建会话对象。
- 数据包：PSH+ACK，payload=UDP 载荷，seq 按 payload 长度递增，
  ack=对端已知的 next-expected-seq（仅用于报文表观合法，不驱动逻辑）。
- keepalive：连接建立后若一段时间无数据，client 定期发送空 ACK，
  用于保活中间 NAT/防火墙的 conntrack，同时 server 用它刷新会话活跃时间。
- 拆除：进程退出/会话超时发 FIN 或 RST 清理；server 端会话空闲超时
  （默认 120s，可配置）自动回收。

checksum：IP 头 checksum 和 TCP 头 checksum（含伪头）都必须手工计算，
`IP_HDRINCL` 下内核不会替你算这两个。

## 3. 内核会主动 RST 的问题 —— iptables（写文档，不在代码里自动跑）

因为本机真实的 TCP/IP 协议栈也会看到这些伪装包的一份拷贝（raw socket
收包是通过 `raw_local_deliver`，和协议栈的 `tcp_v4_rcv` 是两份独立拷贝，
互不影响接收），但因为本机没有真正 `listen()/connect()` 那个四元组，
内核 TCP 栈会认为这是非法段并**回一个 RST**。这个 RST 一旦真的发出去，
会打断伪装、也可能被中间设备识别成连接异常。

修复方式不是丢弃入站包（丢入站包在 `INPUT` chain 会导致 raw socket
自己也收不到，因为两者共享同一次 netfilter 判定），而是只丢内核自己
生成的出站 RST：

```bash
# 服务端：本机监听的伪装端口是 PORT
iptables -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP

# 客户端：远端 server 端口是 PORT（按实际情况把 --dport 换成你连的端口）
iptables -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
```

这两条规则只丢 RST，不影响正常的其它 TCP 连接。持久化（iptables-save /
netfilter-persistent）留给用户自己按发行版处理，文档里说明即可，
udpmimic 本身不代为修改防火墙规则。

## 4. 会话管理（server + client 共用同一套 session/hash/pool 模块，对照 shadowsocks-libev 但去依赖化）

shadowsocks-libev 的 `udprelay.c` + `cache.c` 用 `uthash` 做
`key(ip:port字符串) -> remote_ctx` 的哈希表，`cache_clear()` 定期
**全表**扫一遍按时间戳过期。这里改成手写更贴合场景、且过期是 O(1)
均摊的版本：

```c
struct session {
        struct session *hnext;      /* 哈希链 */
        struct list_head lru;       /* kernel 风格 intrusive 双向链表 */
        uint32_t cli_ip;
        uint16_t cli_port;
        uint32_t snd_nxt;           /* 我方下一个要发的 seq */
        uint32_t rcv_nxt;           /* 期望对方的下一个 seq（填 ack 用） */
        int      remote_fd;         /* 专属 UDP socket，已 connect() 到后端 */
        time_t   last_active;
        uint8_t  state;             /* SYN_RCVD / ESTABLISHED / CLOSING */
};
```

- **对象池**：进程启动时一次性 `calloc(MAX_SESSIONS, sizeof(struct session))`，
  之后不再 malloc/free；空闲对象用侵入式单链表（复用 `hnext` 字段）串成
  freelist。
- **哈希表**：`(cli_ip, cli_port)` 做 key，桶数为 2 的幂，拉链法，链表
  节点就是 pool 里的对象指针，查找/插入 O(1) 均摊。
- **LRU 淘汰**：每次收到该 session 的包，`list_move(&s->lru, &lru_head)`
  移到链表头。定时器（epoll timeout 或 timerfd，比如每 5s 一次）只需从
  **链表尾部**往前扫，遇到第一个还没超时的就停手——因为链表本身按最近
  活跃度有序，不需要像 `cache_clear()` 那样扫全表，过期开销只与本轮
  真正过期的会话数成正比。
- **回程路径零查找**：每个 session 专属一个已 `connect()` 的 UDP fd，
  注册进 epoll 时 `epoll_event.data.ptr = session`，后端 UDP 回包到达时
  **不需要**再查一次哈希表，直接从 epoll 事件里拿到 session 指针——比
  shadowsocks-libev 的 remote_recv_cb 更省一次 hash lookup。

### 4.1 client 端会话表

client 端结构上和 server 端**同构**（同一份 `session.c` 代码，只是
key 的语义和"内层 fd"的语义不同），因为要支持多个本地 UDP 应用：

```c
struct session {
        struct session *hnext;
        struct list_head lru;
        uint32_t key_ip;     /* server: 对端(客户端)ip；client: 恒为0，不用 */
        uint16_t key_port;   /* server: 对端(客户端)port；client: 自己选的 outer tcp 源端口 */
        struct sockaddr_in inner_peer; /* client 专用：这条连接对应的本地 UDP peer 地址 */
        uint32_t snd_nxt;
        uint32_t rcv_nxt;
        int      remote_fd;  /* server 专用：connect() 到后端的 UDP socket；client 不用(-1) */
        time_t   last_active;
        uint8_t  state;
};
```

client 需要两条查找路径，各自一张表，但共享同一个对象池：

- **本地包到达**（本地 UDP socket `recvfrom` 拿到 peer 地址）→ 按
  `inner_peer` 查一张小哈希表，找到已有 session 就直接发；没有就从
  对象池取一个新对象、分配一个当前未占用的 outer TCP 源端口
  （从预留端口段里顺序/环形分配，端口段大小 = `-n` 配置的最大并发本地
  应用数），发 SYN 开始握手。
- **远端包到达**（raw socket 收到来自 server 的包）→ 按包的 TCP
  **目的端口**（也就是我们自己选的那个 outer 源端口）查另一张哈希表
  找到 session，取出 `inner_peer`，`sendto()` 回本地 UDP socket。

两张表的 key 空间都很小（外层端口段是我们自己分配的，天然无冲突），
用同一套通用哈希表实现即可，不需要为 client 单独写一套。

server 端只需要"远端包到达 → 按 (src_ip,src_port) 查表"这一条路径，
回程路径靠 epoll `data.ptr` 直接拿 session（见上文），不需要第二张表。

## 5. 事件循环 / 并发模型

- 单线程 epoll，边缘触发（EPOLLET）+ 非阻塞 fd，每次可读事件用
  `recvfrom` 循环读到 `EAGAIN` 为止（避免饿死其它 fd，同时批量处理）。
- server 端两类 fd 在同一个 epoll：1 个 raw socket（所有客户端的伪装包）
  + N 个 per-session UDP socket（后端回包）。
- v1 不做多线程/`SO_REUSEPORT` 分片，先把单线程路径做到足够快
  （目标：纯用户态转发，单核打满万兆网卡对这种小包场景基本是够的）。
  多线程分片作为后续可选项写在"未来优化"里，不在 v1 实现，避免过早复杂化。

## 6. 目录/文件划分

```
udpmimic/
├── src/
│   ├── common.h      # 公共类型、日志宏、错误处理宏（goto 风格）
│   ├── checksum.h/c  # IP/TCP checksum、伪头计算
│   ├── rawsock.h/c   # raw socket 创建、IP+TCP 头构造/解析
│   ├── session.h/c   # 哈希表 + 对象池 + LRU（仅 server 用）
│   ├── list.h         # kernel 风格 intrusive doubly-linked list（精简版 list.h）
│   ├── client.c       # client 事件循环 + main
│   └── server.c       # server 事件循环 + main
├── Makefile            # 无第三方依赖，-O2 -Wall，两个可执行文件 udpmimic-c / udpmimic-s（或一个二进制 -c/-s 切换）
└── README.md            # 用法 + iptables 规则说明 + 测试步骤
```

倾向于**一个二进制**、靠 `-c`/`-s` 切换角色（像 udp2raw 一样），减少
部署时要传的文件数量，对双机 scp 测试更友好。

## 7. CLI 参数（初版，够用为止）

```
udpmimic -s -l 0.0.0.0:4096 -r 127.0.0.1:1194 [-n 4096] [-t 120] [-v]
udpmimic -c -l 127.0.0.1:1195 -r <server_ip>:4096 [-n 256] [-k 20] [-v]
```

- `-s`/`-c`：server / client 模式
- `-l`：本地监听地址
  - server：伪装 TCP 监听地址:端口
  - client：本地 UDP socket 绑定地址:端口（单个 socket，靠 `recvfrom`
    的 peer 地址天然区分背后有几个不同的本地应用/端口在用它，不需要
    分别配置多个 `-l`）
- `-r`：远端地址（server：真实 UDP 后端地址:端口；client：udpmimic server 的公网地址:端口）
- `-n`：最大并发会话数（server：最大客户端数；client：最大同时使用的本地应用数），决定对象池大小和 client 的 outer 端口段大小，默认 server 4096 / client 256
- `-t`：会话空闲超时秒数，默认 120
- `-k`：client keepalive 间隔秒数，默认 20
- `-v`：verbose 日志

## 8. 测试计划

1. 本地先起 `nc -u -l -p 1194`（或简单 UDP echo 脚本）模拟后端服务，
   本机单机跑 client+server+echo 验证协议正确性（先不牵扯双机/防火墙）。
2. 编译产物 scp 到测试机 `root@72.18.81.227 -p 1822` 双机对跑：
   本机当 client，测试机当 server（或反过来），中间验证：
   - 三次握手是否正确建立 session
   - UDP 数据双向转发是否正常（用 iperf/nc -u 或直接跑一个真实的
     OpenVPN/WireGuard 隧道验证端到端）
   - 不加 iptables 规则时观察是否出现内核自动 RST 导致连接异常，
     加上第 3 节的规则后验证问题消失
   - 多客户端并发（多开几个本地 client 进程指向同一 server）验证
     session 表按 (ip,port) 正确区分、超时正确回收
   - 单个 client 进程同时对接多个本地 UDP 应用（比如同时起两个
     `nc -u` 本地对端指向同一个 client `-l` 地址），验证 client 端
     两张表能正确按本地 peer / outer 端口互不串包
3. 用 `tcpdump -i any tcp port <PORT>` 抓包核对报文是否"看起来像"
   正常 TCP（握手+数据+keepalive），供后续对照真实防火墙场景使用。

## 9. v1 不做、留作后续可选项

- IPv6
- 多线程/SO_REUSEPORT 分片扩展吞吐
- 可选的轻量混淆（用户明确说不需要加密，这里不主动加）
- ICMP/纯UDP 伪装模式（udp2raw 的其它 raw-mode，这里只做 fake-tcp）
- 更贴近真实 TCP 的时序抖动/窗口模拟（目前只保证字段合法，不做高级
  反 DPI 行为学）
