/* rawsock.c - build/parse/send/receive fake-TCP packets on raw sockets. */
#include <unistd.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "common.h"
#include "checksum.h"
#include "rawsock.h"

/*
 * Conservative safe size: we set DF (IPv4) / never fragment (IPv6,
 * which has no router fragmentation at all) and would rather drop an
 * oversized datagram than have it silently vanish into a middlebox
 * that hates fragments. Comfortably covers typical VPN traffic MTUs;
 * jumbo payloads are out of scope (see DESIGN.md).
 */
#define SAFE_MTU 1500U

static uint16_t next_ip_id(void)
{
	static uint16_t ip_id;
	static int seeded;

	if (!seeded) {
		uint16_t seed;

		if (getrandom(&seed, sizeof(seed), 0) == sizeof(seed))
			ip_id = seed;
		seeded = 1;
	}
	return ip_id++;
}

int rawsock_open(sa_family_t family)
{
	int fd, one = 1;
	int level = (family == AF_INET6) ? IPPROTO_IPV6 : IPPROTO_IP;
	int optname = (family == AF_INET6) ? IPV6_HDRINCL : IP_HDRINCL;
	int rcvbuf = 4 * 1024 * 1024;

	fd = socket(family, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		pr_err("socket(SOCK_RAW, IPPROTO_TCP, %s): %s (need root/CAP_NET_RAW)",
		       family == AF_INET6 ? "AF_INET6" : "AF_INET", strerror(errno));
		return -1;
	}

	if (setsockopt(fd, level, optname, &one, sizeof(one)) < 0) {
		pr_err("setsockopt(HDRINCL): %s", strerror(errno));
		close(fd);
		return -1;
	}

	/* Best-effort: a bigger receive buffer just reduces avoidable loss
	 * under bursty traffic; our payload semantics already tolerate loss. */
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

	return fd;
}

static void fill_tcp_fields(struct tcphdr *tcp, const struct fake_tcp_hdr *h)
{
	tcp->source = htons(h->src.port);
	tcp->dest = htons(h->dst.port);
	tcp->seq = htonl(h->seq);
	tcp->ack_seq = htonl(h->ack);
	tcp->doff = 5;
	tcp->syn = !!(h->flags & TCPF_SYN);
	tcp->ack = !!(h->flags & TCPF_ACK);
	tcp->psh = !!(h->flags & TCPF_PSH);
	tcp->fin = !!(h->flags & TCPF_FIN);
	tcp->rst = !!(h->flags & TCPF_RST);
	tcp->window = htons(h->window);
	tcp->urg_ptr = 0;
	tcp->check = 0;
}

static void fill_hdr_flags(struct fake_tcp_hdr *h, const struct tcphdr *tcp)
{
	h->seq = ntohl(tcp->seq);
	h->ack = ntohl(tcp->ack_seq);
	h->window = ntohs(tcp->window);
	h->flags = 0;
	if (tcp->syn) h->flags |= TCPF_SYN;
	if (tcp->ack) h->flags |= TCPF_ACK;
	if (tcp->psh) h->flags |= TCPF_PSH;
	if (tcp->fin) h->flags |= TCPF_FIN;
	if (tcp->rst) h->flags |= TCPF_RST;
}

static int build_v4(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		     const uint8_t *payload, size_t payload_len)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	size_t total = sizeof(*ip) + sizeof(*tcp) + payload_len;

	if (total > bufcap || total > SAFE_MTU)
		return -1;

	memset(buf, 0, sizeof(*ip) + sizeof(*tcp));

	ip = (struct iphdr *)buf;
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)total);
	ip->id = htons(next_ip_id());
	ip->frag_off = htons(0x4000); /* DF: real TCP stacks set it, and we'd
					* rather drop an oversized packet than
					* have it silently fragmented/dropped. */
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = h->src.ip.v4.s_addr;
	ip->daddr = h->dst.ip.v4.s_addr;
	ip->check = 0;
	ip->check = inet_checksum(ip, sizeof(*ip), 0);

	tcp = (struct tcphdr *)(buf + sizeof(*ip));
	fill_tcp_fields(tcp, h);

	if (payload_len)
		memcpy(buf + sizeof(*ip) + sizeof(*tcp), payload, payload_len);

	tcp->check = tcp4_checksum(ip, tcp, payload, payload_len);

	return (int)total;
}

static int build_v6(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		     const uint8_t *payload, size_t payload_len)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	size_t total = sizeof(*ip6) + sizeof(*tcp) + payload_len;

	if (total > bufcap || total > SAFE_MTU)
		return -1;

	memset(buf, 0, sizeof(*ip6) + sizeof(*tcp));

	ip6 = (struct ip6_hdr *)buf;
	ip6->ip6_flow = htonl(6u << 28); /* version=6, traffic class/flow label = 0 */
	ip6->ip6_plen = htons((uint16_t)(sizeof(*tcp) + payload_len));
	ip6->ip6_nxt = IPPROTO_TCP;
	ip6->ip6_hlim = 64;
	ip6->ip6_src = h->src.ip.v6;
	ip6->ip6_dst = h->dst.ip.v6;

	tcp = (struct tcphdr *)(buf + sizeof(*ip6));
	fill_tcp_fields(tcp, h);

	if (payload_len)
		memcpy(buf + sizeof(*ip6) + sizeof(*tcp), payload, payload_len);

	tcp->check = tcp6_checksum(&ip6->ip6_src, &ip6->ip6_dst, tcp, payload, payload_len);

	return (int)total;
}

int rawsock_build(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		   const uint8_t *payload, size_t payload_len)
{
	if (h->src.family == AF_INET6)
		return build_v6(buf, bufcap, h, payload, payload_len);
	return build_v4(buf, bufcap, h, payload, payload_len);
}

int rawsock_send(int fd, const uint8_t *pkt, size_t pkt_len, const struct netaddr *dst)
{
	struct sockaddr_storage ss;
	struct netaddr d = *dst;
	socklen_t len;
	ssize_t n;

	/* The port is meaningless for a raw socket (the real destination is
	 * inside the packet we built); the IPv6 stack is strict and returns
	 * EINVAL on a nonzero sin6_port here, unlike IPv4's more lenient one. */
	d.port = 0;
	netaddr_to_sockaddr(&d, &ss, &len);

	n = sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)&ss, len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		pr_warn("raw sendto: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int parse_v4(const uint8_t *buf, size_t len, struct fake_tcp_hdr *h,
		     const uint8_t **payload, size_t *payload_len)
{
	const struct iphdr *ip;
	const struct tcphdr *tcp;
	size_t ip_hlen, tcp_hlen, total;

	if (len < sizeof(*ip))
		return -1;

	ip = (const struct iphdr *)buf;
	ip_hlen = (size_t)ip->ihl * 4;
	if (ip_hlen < sizeof(*ip) || len < ip_hlen + sizeof(*tcp))
		return -1;
	if (ip->protocol != IPPROTO_TCP)
		return -1;

	tcp = (const struct tcphdr *)(buf + ip_hlen);
	tcp_hlen = (size_t)tcp->doff * 4;
	if (tcp_hlen < sizeof(*tcp) || ip_hlen + tcp_hlen > len)
		return -1;

	total = ntohs(ip->tot_len);
	if (total < ip_hlen + tcp_hlen || total > len)
		total = len; /* tolerate padded frames; clamp to what we got */

	h->src.family = AF_INET;
	h->src.ip.v4.s_addr = ip->saddr;
	h->src.port = ntohs(tcp->source);
	h->dst.family = AF_INET;
	h->dst.ip.v4.s_addr = ip->daddr;
	h->dst.port = ntohs(tcp->dest);
	fill_hdr_flags(h, tcp);

	*payload = buf + ip_hlen + tcp_hlen;
	*payload_len = total - (ip_hlen + tcp_hlen);
	return 0;
}

/*
 * buf is bare TCP header+payload here -- no IPv6 base header (see the
 * rawsock_parse() doc comment in rawsock.h). h->src.ip/h->dst.ip are
 * left zeroed; the caller fills them in from elsewhere.
 */
static int parse_v6(const uint8_t *buf, size_t len, struct fake_tcp_hdr *h,
		     const uint8_t **payload, size_t *payload_len)
{
	const struct tcphdr *tcp;
	size_t tcp_hlen;

	if (len < sizeof(*tcp))
		return -1;

	tcp = (const struct tcphdr *)buf;
	tcp_hlen = (size_t)tcp->doff * 4;
	if (tcp_hlen < sizeof(*tcp) || tcp_hlen > len)
		return -1;

	h->src.family = AF_INET6;
	h->src.port = ntohs(tcp->source);
	h->dst.family = AF_INET6;
	h->dst.port = ntohs(tcp->dest);
	fill_hdr_flags(h, tcp);

	*payload = buf + tcp_hlen;
	*payload_len = len - tcp_hlen;
	return 0;
}

int rawsock_parse(sa_family_t family, const uint8_t *buf, size_t len,
		   struct fake_tcp_hdr *h, const uint8_t **payload, size_t *payload_len)
{
	memset(h, 0, sizeof(*h));

	if (family == AF_INET6)
		return parse_v6(buf, len, h, payload, payload_len);
	return parse_v4(buf, len, h, payload, payload_len);
}

void rawsock_filter_port(int fd, sa_family_t family, enum tcp_port_field field, uint16_t port)
{
	/* TCP source/dest port sit at bytes 0-1 / 2-3 of the TCP header.
	 * IPv4 raw sockets hand us the IP header first, whose length is
	 * variable (options) -- BPF_LDX|BPF_MSH computes it into X the
	 * same way tcpdump's own "tcp port N" filters do. IPv6 raw
	 * sockets hand us the TCP header directly at offset 0 (see
	 * rawsock_parse()'s doc comment), so no header-length step or
	 * indexed load is needed there. */
	uint32_t off = (field == TCP_PORT_SRC) ? 0 : 2;
	struct sock_filter v4[] = {
		BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0),
		BPF_STMT(BPF_LD | BPF_H | BPF_IND, off),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_filter v6[] = {
		BPF_STMT(BPF_LD | BPF_H | BPF_ABS, off),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog prog;

	if (family == AF_INET6) {
		prog.len = (unsigned short)(sizeof(v6) / sizeof(v6[0]));
		prog.filter = v6;
	} else {
		prog.len = (unsigned short)(sizeof(v4) / sizeof(v4[0]));
		prog.filter = v4;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
		pr_warn("SO_ATTACH_FILTER: %s (continuing unfiltered, just slower)", strerror(errno));
}
