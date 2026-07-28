# udpmimic design notes

## 0. Goals and scope

Functionally this targets `udp2raw`'s **fake-tcp** mode (disguise UDP as a
normal-looking TCP handshake + data stream to get past firewalls/QoS that
throttle or block UDP), but deliberately drops the following in exchange for
being as small and fast as possible:

- No encryption, no HMAC auth, no anti-replay (explicitly out of scope)
- Fake-tcp disguise only (no icmp/udp disguise modes)
- Linux + epoll only, libc only, no libev/uthash/libpcap dependency
- IPv4 and IPv6, dual-stack when bound to `[::]`

What *is* the focus:

- Efficient one-to-many client session management on the server side
  (inspired by shadowsocks-libev's approach, but hand-rolled without the
  uthash/ev_tstamp dependency, and tuned for this specific workload)
- Zero heap allocation on the hot path (stack buffers + a session object pool)
- Edge-triggered epoll, non-blocking, Linux-kernel-style C (goto-based error
  handling, intrusive lists, tight naming)

## 1. Topology

```
N local UDP apps                                          real UDP backend (single address)
(e.g. several OpenVPN/WireGuard client processes)          (e.g. an OpenVPN/WireGuard server)
      |  UDP (one local socket, different peers)                  ^  UDP (dedicated fd per session)
      v                                                            |
  [udpmimic -c client]  == N independent fake-TCP "connections" ==>  [udpmimic -s server]
   local UDP socket (1,           raw socket (1,        raw socket (1 or 2       N UDP sockets
   recvfrom/sendto tells          different outer       for dual-stack)          (one per session,
   peers apart)                   TCP src port per        distinguished by         connect()ed to
                                   session)                 (src_ip,src_port))       the backend)
```

- **client**: talks to exactly one remote server, but can relay **multiple**
  local UDP peers at once (several different local processes/ports). Each
  local peer gets its own independent fake-TCP "connection" (its own outer
  TCP source port + seq/ack state) rather than being multiplexed inside a
  single connection with a hand-rolled inner framing protocol -- this fully
  reuses the server's existing multi-session machinery instead of inventing
  a second one.
- **server**: one (or two, for dual-stack) raw socket(s) receive all
  disguised TCP packets and demux by `(src_ip, src_port)` into N sessions
  (server-side, it makes no difference whether those N sessions are N
  different physical clients or one client process relaying N different
  local apps -- the two look identical). Each session gets its own UDP
  socket `connect()`ed to the same configured backend address.

## 2. Wire protocol

We don't run a real TCP stack for the handshake/retransmission -- we
hand-build IPv4/IPv6 + TCP headers ourselves, payload is the raw UDP
payload (no length prefix: each raw packet we send and receive corresponds
to exactly one UDP datagram, since we're not relying on kernel TCP stream
reassembly on either end).

Field strategy:

- IPv4: `IP_HDRINCL` raw socket, we build the whole IPv4 header ourselves.
- IPv6: `IPV6_HDRINCL` raw socket for *sending*; **on receive, IPv6 raw
  sockets never deliver the IPv6 base header to userspace at all** (this is
  standard RFC 3542 behavior, not a bug) -- `recvfrom()` gives us bare
  TCP-header-plus-payload, and the kernel-filled peer address from
  `recvfrom()` itself is how we recover the sender's IP (there is no
  equivalent for the packet's *destination* address short of
  `IPV6_RECVPKTINFO`; see §4 for how the server works around that).
- seq/ack exist purely so the stream looks like a normal, monotonically
  progressing TCP flow to anything doing packet inspection -- there is
  **no real retransmission or reordering**. This is the key simplification:
  since the underlying traffic is UDP, loss semantics stay UDP-like (a lost
  packet is just gone, exactly like real UDP), so none of TCP's reliability
  machinery is needed.
- Handshake: SYN -> SYN+ACK -> ACK before the session is usable server-side.
  The client is allowed to combine SYN+PSH to piggyback its very first
  datagram on the opening segment (matches real TCP Fast Open framing: SYN
  occupies one sequence number, the payload's first byte is right after
  it) -- this avoids a round trip and avoids buffering that first datagram.
- Data: PSH+ACK, payload = UDP payload, seq advances by payload length.
  `ack` is always just "peer's last-seen seq + len", recomputed fresh from
  whatever packet arrives rather than tracked cumulatively -- since we
  don't validate/reject out-of-order segments anyway, this is simpler and
  self-heals if anything upstream reorders.
- Keepalive: client periodically sends a bare ACK if idle, both to keep
  any NAT/conntrack state alive along the path and to refresh the
  session's last-active time server-side.
- Teardown: RST on process exit / idle timeout. (FIN would be more
  "correct" TCP-wise, but RST is simpler to reason about for immediate
  teardown and is what's actually implemented.)

Checksums (IPv4 header checksum, and the TCP checksum incl. pseudo-header
for both families) are always computed by hand -- `IP_HDRINCL`/
`IPV6_HDRINCL` never do this for you.

A few small, deliberate touches for realism/robustness, informed by
reading `udp2raw`'s own source for lessons already learned there (see §8):

- **DF is set on IPv4 packets** (real TCP stacks essentially always set
  it), and payload size is capped so we never rely on IP fragmentation --
  fragments get dropped by enough middleboxes that depending on them would
  make large payloads *less* reliable, not more. IPv6 has no router
  fragmentation at all, so this is naturally a non-issue there.
- **IPv4 IP ID is seeded from `getrandom()`** at first use instead of
  always starting at 0 -- a static, restart-identical ID sequence is a
  cheap fingerprinting tell.
- **SO_RCVBUF is raised** on the raw sockets -- a larger buffer just cuts
  avoidable loss under bursty traffic; not a correctness fix (our payload
  semantics already tolerate loss), just cheap insurance.

## 3. The kernel will try to RST our own packets -- iptables (documented, not automated)

The real local TCP/IP stack also sees a copy of every disguised packet
(raw-socket delivery and the real protocol handler are two independent
fan-outs of the same incoming packet, not mutually exclusive), but since
there's no genuine `listen()`/`connect()`ed four-tuple behind it, the
kernel's TCP code treats it as an invalid segment and tries to answer with
an RST. If that RST actually leaves the box, it breaks the disguise and
can confuse anything doing connection tracking in between.

The fix isn't to drop inbound packets at `INPUT` (that would stop our own
raw socket from seeing them too -- both fan-outs are gated by the same
netfilter verdict). Instead, only drop the kernel's own **outbound** RST:

```bash
# server: PORT is the disguised listen port
iptables  -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP   # IPv4
ip6tables -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP   # IPv6, if used

# client: PORT is the remote server's port
iptables  -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
ip6tables -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
```

These two rules only ever touch RST packets; nothing else on the host is
affected. Persisting them across reboots is left to the user (`iptables-save`,
`netfilter-persistent`, etc, distro-dependent) -- udpmimic never modifies
firewall rules itself.

## 4. Server-side session management (shadowsocks-libev-inspired, dependency-free), and one IPv6-specific twist

shadowsocks-libev's `udprelay.c` + `cache.c` keys a `uthash` table by a
`"ip:port"` string and periodically **full-scans** the table by timestamp
to expire idle entries (`cache_clear()`). This is reworked into a hand-rolled
version that fits this workload better and amortizes expiry to O(1):

```c
struct session {
        struct session *hnext;      /* hash chain */
        struct list_head lru;       /* kernel-style intrusive doubly-linked list */
        struct netaddr   key;       /* server: the client's outer (ip, port); client: (family, port only) */
        struct netaddr   local;     /* our own address to send this session's replies from */
        struct netaddr   inner_peer;/* client only: which local UDP peer this maps to */
        uint32_t snd_nxt;
        uint32_t rcv_nxt;
        int      remote_fd;         /* server only: UDP socket connect()ed to the backend */
        time_t   last_active;
        uint8_t  state;             /* SYN_SENT / SYN_RCVD / ESTABLISHED / CLOSING */
};
```

- **Object pool**: the whole capacity is `calloc()`'d once at startup; no
  malloc/free after that. Free slots are chained through the same `hnext`
  field as a singly-linked freelist (never both a hash-chain node and a
  freelist node at once, so reusing the field is safe).
- **Hash table**: keyed by `struct netaddr` (family-tagged, holds either a
  4- or 16-byte address). Bucket count is a power of two, chaining via
  pool-owned pointers; O(1) amortized lookup/insert. Hash/equality only
  ever compare the *family-appropriate* prefix of the address (4 bytes for
  v4, 16 for v6), so unused tail bytes in the union never need to be
  zeroed by every call site -- one less footgun.
- **LRU eviction**: every packet touching a session does `list_move(&s->lru,
  &lru_head)`. A periodic timer (epoll timeout / timerfd, every ~5s) only
  needs to walk from the **tail** of the list and stop at the first entry
  that isn't expired yet -- since the list stays ordered by recency, cost
  is proportional to how many sessions actually expired this round, not
  to the table size. (Unlike `cache_clear()`'s full-table scan.)
- **Zero extra lookup on the return path**: each session's dedicated
  backend UDP fd is registered with `epoll_event.data.ptr = session`, so a
  backend reply doesn't need a second hash lookup to find its session --
  one step cheaper than shadowsocks-libev's `remote_recv_cb`.

### 4.1 The client's session table

The client is **structurally the same** (same `session.c`, just different
meaning for the key and the "inner fd"), because it needs to support
multiple local UDP peers:

The client needs two lookup paths into the same object pool:

- **A local packet arrives** (`recvfrom()` on the local UDP socket gives
  us the peer's address) -> looked up in a small hash table keyed by
  `inner_peer`. If there's no existing session, grab one from the pool,
  allocate a not-currently-used outer TCP source port from a reserved
  range (sized by `-n`), and send a SYN to start the handshake.
- **A remote packet arrives** (raw socket receives something from the
  server) -> looked up by the packet's TCP **destination port** (i.e. the
  outer port we picked ourselves), in a separate table. Pull out
  `inner_peer` from the session, `sendto()` it back to the local socket.

Both tables reuse the exact same `netaddr_hash()`/`netaddr_equal()`
helpers as the server's primary table -- no separate implementation
needed. The server only ever needs the "remote packet arrived -> look up
by (src_ip,src_port)" path; the return path is free via epoll `data.ptr`
as above, so it doesn't need a second table at all.

### 4.2 IPv6-specific: recovering the destination address

For IPv4, `s->local` (which address we should reply *from*) comes for
free -- the IPv4 raw socket hands us the full IP header on receive, so we
just read the destination address straight out of it. IPv6 raw sockets
don't give us that (§2), so on a session's first SYN, if the client
arrived over IPv6 the server instead does a `connect()`+`getsockname()`
routing-table lookup toward the client's address -- the same trick the
client already uses at startup to learn its own outbound address (see
`netaddr_route_lookup()` in `common.c`, shared by both). This only costs
two syscalls once per new session, not per packet, and correctly picks
the right local address to reply from even on a multi-homed IPv6 host
(our real two-machine test server has three different global IPv6
addresses -- exactly the scenario this matters for).

One consequence: since there's no cheap per-packet destination address
for IPv6, the server does **not** filter incoming IPv6 packets by a
specific configured listen address the way it does for IPv4 -- only the
destination *port* is checked for IPv6. This is a deliberate, documented
simplification (resolving it per-packet would cost a route lookup on
every single packet, not just per session); port matching alone is still
the primary discriminator and is sufficient in practice.

## 5. Event loop / concurrency model

- Single-threaded epoll, edge-triggered (`EPOLLET`) + non-blocking fds;
  every readable event drains with a `recvfrom`/`recv` loop until
  `EAGAIN` (correct ET usage, and processes in batches instead of
  round-robining one packet at a time).
- Server-side, two kinds of fd share one epoll set: the raw socket(s)
  (all clients' disguised packets) and N per-session UDP sockets (backend
  replies).
- **A classic BPF filter is attached to every raw socket**
  (`SO_ATTACH_FILTER`), matching on the relevant TCP port (dest port for
  the server, source port for the client) so the kernel drops irrelevant
  TCP traffic before it ever reaches userspace. A raw `IPPROTO_TCP` socket
  otherwise receives *every* TCP packet the host sees, not just ours --
  this was an actual, measured cost during development (continuous
  `recvfrom()` wakeups from unrelated background TCP traffic on a busy
  box), not a speculative optimization.
- v1 doesn't do multi-threading / `SO_REUSEPORT` sharding; the
  single-threaded path is fast enough for this workload's packet sizes
  and gets to stay simple. Sharding is listed as a possible future
  addition, not implemented now, to avoid premature complexity.

## 6. Layout

```
udpmimic/
├── src/
│   ├── common.h/c    # struct netaddr (family-tagged address), logging, CLI config, small helpers
│   ├── checksum.h/c  # IPv4 and IPv6 TCP checksums (with pseudo-header)
│   ├── rawsock.h/c   # raw socket open/build/parse/send, BPF port filter
│   ├── session.h/c   # hash table + object pool + LRU (shared by server and client)
│   ├── list.h        # small kernel-style intrusive doubly-linked list
│   ├── client.c       # client event loop + entry point
│   └── server.c       # server event loop + entry point
├── Makefile            # no third-party dependencies, -O2 -Wall, single `udpmimic` binary
└── README.md            # usage + iptables rules + build/test instructions
```

One binary, `-c`/`-s` picks the role (like `udp2raw`) -- fewer files to
juggle when deploying to a second machine.

## 7. CLI

```
udpmimic -s -l 0.0.0.0:4096 -r 127.0.0.1:1194 [-n 4096] [-t 120] [-v]
udpmimic -c -l 127.0.0.1:1195 -r <server_ip>:4096 [-n 256] [-k 20] [-v]
```

- `-s` / `-c`: server / client mode
- `-l`: local address
  - server: the disguised listen address:port. `[::]:PORT` also accepts
    IPv4 clients on the same port (dual-stack; opens a second, IPv4 raw
    socket internally, feeding the same session table).
  - client: local UDP bind address:port (one socket; `recvfrom()`'s peer
    address is how multiple local apps sharing it get told apart, so
    there's no need to run separate udpmimic processes per local app).
- `-r`: remote address (server: the real UDP backend; client: the udpmimic
  server's address)
- `-n`: max concurrent sessions (server: max clients; client: max local
  apps at once) -- sizes the object pool and, client-side, the outer port
  range. Default 4096 (server) / 256 (client).
- `-t`: idle session timeout in seconds, default 120
- `-k`: client keepalive interval in seconds, default 20
- `-v`: verbose logging

Addresses are `ip:port` for IPv4, `[ip6]:port` for IPv6.

## 8. What we checked against udp2raw, and what we deliberately didn't adopt

Read through `wangyu-/udp2raw`'s raw-socket/fake-tcp source, README and
comments specifically looking for hard-won fixes a naive reimplementation
would miss. Already adopted where relevant (§2, §5): DF flag + payload
size cap, randomized IP ID seed, bigger `SO_RCVBUF`, and a BPF port filter
(their equivalent uses `PF_PACKET` + a link-layer BPF filter since they
receive via a link-layer tap; ours is `AF_INET(6) SOCK_RAW` with a
correspondingly simpler IP/TCP-layer filter).

Deliberately **not** adopted, each because it targets a threat model or
feature surface we explicitly excluded:

- **TCP options** (MSS on SYN, timestamps on data, `doff` > 5): udp2raw
  sends both; we send a bare 20-byte header on every packet. A real OS
  essentially always includes at least MSS on a SYN, so this is a genuine
  fingerprinting gap -- but closing it fully means variable-length
  options, per-session timestamp-echo state, and checksum math for a
  variable header length, for a goal (defeating OS/DPI fingerprinting)
  that isn't ours: we're trying to get past UDP-hostile QoS/firewalls, not
  survive nation-state-grade traffic analysis.
- **Randomized TCP window size**: same reasoning, skipped; we use a fixed
  65535 everywhere.
- **`conv_id` session continuity across a client's NAT rebind**: udp2raw
  has a whole connection-ID abstraction so a client's logical session
  survives its outer `(ip,port)` changing (e.g. mobile handoff). We
  identify sessions purely by outer tuple, so a rebind looks like a brand
  new client and the old session just times out on its own (no leak, no
  crash -- just an invisible reconnect from the app's point of view).
  Implementing continuity would need exactly the kind of inner
  protocol/auth layer we've ruled out (an unauthenticated conv_id would
  also be trivially abusable to hijack another session). Documented here
  as a known, accepted limitation rather than silently gapped.
- **conntrack `INVALID` classification**: neither udp2raw nor we use
  `NOTRACK` (raw table). A host with strict conntrack hardening (`-m
  conntrack --ctstate INVALID -j DROP`, independent of our own RST-drop
  rule) could still drop this traffic. Not something to fix in code
  (matches udp2raw's own scope); if you hit this, try adding
  `iptables -t raw -A OUTPUT -p tcp --sport PORT -j NOTRACK` (and the
  PREROUTING equivalent on the peer).

## 9. Testing

1. Local loopback: run a UDP echo target, start `-s`/`-c` pointed at each
   other, confirm round-trip forwarding works before touching a second
   machine or firewall rules.
2. Copy the built binary to a second machine, run one side as `-s` and the
   other as `-c` over a real network path, and check:
   - the three-way handshake actually completes; `tcpdump -i any tcp port
     <PORT>` to confirm the packets look like ordinary TCP (handshake +
     data + keepalive);
   - data forwards correctly both directions (works well as an end-to-end
     check by tunneling a real OpenVPN/WireGuard session through it);
   - without the iptables rule from §3, watch for the kernel's own RST
     breaking sessions; confirm it stops once the rule is added;
   - multiple concurrent sessions (several client processes against one
     server, and one client relaying several local peers at once) are
     correctly kept apart and correctly reaped after the idle timeout.
3. Repeat the above for IPv6 (`[::1]` locally is enough to exercise all
   the v6-specific code paths, including the dual-stack `[::]` listen
   case) if the target network path actually routes IPv6 between the two
   machines -- some cloud/sandbox networks assign global-looking IPv6
   addresses per host without actually routing between hosts, which is an
   environment/network issue to rule out first, not a udpmimic bug, if v6
   traffic between two specific boxes silently goes nowhere.

## 10. Deliberately out of scope for v1

- Multi-threading / `SO_REUSEPORT` sharding for higher throughput
- Optional lightweight obfuscation (explicitly not requested -- no crypto
  here at all)
- ICMP/plain-UDP disguise modes (udp2raw's other raw-modes; this project
  only does fake-tcp)
- Anti-fingerprinting behavioral realism beyond "the fields are valid"
  (see §8)
