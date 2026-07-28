# udpmimic

**English | [简体中文](README.zh-CN.md)**

Disguise UDP traffic as ordinary TCP to get past firewalls and QoS that
throttle or block UDP. A minimal, dependency-free reimplementation of
[`udp2raw`](https://github.com/wangyu-/udp2raw)'s fake-tcp mode: no
encryption, no auth, no anti-replay, no fancy anti-fingerprinting — just
the disguise, built for raw speed.

- **Linux only**, single-threaded epoll, raw sockets — no libev, no
  uthash, no libpcap. Just libc.
- **IPv4 and IPv6**, including dual-stack (`[::]` accepts both on the
  same port).
- **One server, many clients.** Server-side session lookup is O(1)
  (hash table + object pool, zero heap allocation on the hot path), with
  amortized O(1) idle-session eviction via an LRU list — not a
  full-table scan.
- **One client, many local apps.** A single client process can relay
  several different local UDP peers at once, each over its own
  independent fake-TCP "connection."
- A classic BPF filter is attached to the raw socket so the kernel drops
  irrelevant TCP traffic before it reaches userspace — a raw
  `IPPROTO_TCP` socket otherwise sees *every* TCP packet on the host.

See [DESIGN.md](DESIGN.md) for the wire protocol, session management
design, and what was deliberately left out (and why).

## Build

```bash
make
```

Pure C, no third-party dependencies. Produces a single `udpmimic`
binary; role is picked with `-s`/`-c`, so one file is all you need to
copy to a second machine.

## Usage

Server (runs somewhere reachable by clients, forwards to the real UDP
service — e.g. an OpenVPN/WireGuard server):

```bash
./udpmimic -s -l 0.0.0.0:4096 -r 127.0.0.1:1194 [-n 4096] [-t 120] [-v]
```

Client (runs wherever your UDP app is; the app keeps talking to a normal
local UDP port, traffic gets disguised as TCP underneath):

```bash
./udpmimic -c -l 127.0.0.1:1195 -r <server_ip>:4096 [-n 256] [-k 20] [-v]
```

Needs root or `CAP_NET_RAW` (raw sockets). Addresses are `ip:port` for
IPv4 or `[ip6]:port` for IPv6 — e.g. `-l [::]:8390` listens on IPv6 *and*
accepts IPv4 clients on the same port (dual-stack).

| flag | meaning | default |
|---|---|---|
| `-s` / `-c` | server / client mode | required |
| `-l ip:port` | server: disguised listen address; client: local UDP bind address | required |
| `-r ip:port` | server: real UDP backend; client: udpmimic server address | required |
| `-n N` | max concurrent sessions (server: clients; client: local apps) | 4096 / 256 |
| `-t sec` | idle session timeout | 120 |
| `-k sec` | client keepalive interval | 20 |
| `-v` | verbose logging | off |

## Required firewall rule

The host's real TCP/IP stack also sees a copy of every disguised packet,
and — since there's no genuine socket behind it — tries to answer with an
RST. Left alone, that RST breaks the disguise. Drop just the kernel's
own outbound RST (this doesn't touch any other traffic):

```bash
# server, PORT = your -l port
iptables  -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP
ip6tables -A OUTPUT -p tcp --sport PORT --tcp-flags RST RST -j DROP   # if using IPv6

# client, PORT = the server's port
iptables  -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
ip6tables -A OUTPUT -p tcp --dport PORT --tcp-flags RST RST -j DROP
```

Persist these however your distro normally persists iptables rules —
udpmimic never touches firewall rules itself.

## Known limitations

- No encryption/auth by design — treat this purely as a disguise layer,
  not a security boundary.
- A client's session is tied to its outer `(ip, port)`; if that changes
  mid-session (e.g. a NAT rebind), the old session just times out and a
  new one starts — there's no `udp2raw`-style connection-ID continuity.
- If a host has strict conntrack hardening (`-m conntrack --ctstate
  INVALID -j DROP`), traffic may still get dropped independent of the
  rule above; try adding a `NOTRACK` rule in the `raw` table if you hit
  this.

## CI

`.github/workflows/release.yml` cross-compiles static `musl` binaries
for x86_64/aarch64/armv7/armv5/mips/mipsel on every push and attaches
them to GitHub Releases on version tags — handy for routers/embedded
targets.
