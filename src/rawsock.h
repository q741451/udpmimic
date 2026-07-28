/* rawsock.h - fake-TCP framing over IP_HDRINCL/IPV6_HDRINCL raw sockets. */
#ifndef UDPMIMIC_RAWSOCK_H
#define UDPMIMIC_RAWSOCK_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#include "common.h"

/* Flags we actually use; kept as plain bits so callers can OR them. */
#define TCPF_SYN 0x01
#define TCPF_ACK 0x02
#define TCPF_PSH 0x04
#define TCPF_FIN 0x08
#define TCPF_RST 0x10

struct fake_tcp_hdr {
	struct netaddr src;	/* .ip = IP src addr, .port = TCP source port */
	struct netaddr dst;	/* .ip = IP dst addr, .port = TCP dest port */
	uint32_t seq;		/* host byte order */
	uint32_t ack;
	uint8_t  flags;
	uint16_t window;
};

/* Opens the raw socket for one address family (AF_INET or AF_INET6). */
int rawsock_open(sa_family_t family);

/*
 * Build one IP+TCP packet with the given payload into buf (caller
 * owns buf, must be at least UDPMIMIC_MAX_PKT bytes). Returns the
 * total packet length, or -1 on overflow. h->src.family selects
 * IPv4 vs IPv6 framing.
 */
int rawsock_build(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		   const uint8_t *payload, size_t payload_len);

/* sendto() a pre-built packet produced by rawsock_build(). */
int rawsock_send(int fd, const uint8_t *pkt, size_t pkt_len, const struct netaddr *dst);

/*
 * Parse an inbound raw packet received on a socket of the given
 * family. On success returns 0, fills *h and points
 * payload/payload_len at the TCP payload inside buf (no copy).
 * Malformed packets return -1.
 *
 * family can't be auto-detected from the buffer: unlike IPv4 raw
 * sockets, IPv6 raw sockets never deliver the IPv6 base header to
 * userspace on receive (RFC 3542) -- buf is bare TCP header+payload
 * for AF_INET6, so h->src/h->dst.ip are left zeroed for v6 and the
 * caller must fill them in some other way (e.g. recvfrom()'s peer
 * address for src; there is no equivalent for dst short of
 * IPV6_RECVPKTINFO, so callers needing it use a routing-lookup trick
 * instead -- see server.c).
 */
int rawsock_parse(sa_family_t family, const uint8_t *buf, size_t len,
		   struct fake_tcp_hdr *h, const uint8_t **payload, size_t *payload_len);

enum tcp_port_field {
	TCP_PORT_SRC,
	TCP_PORT_DST,
};

/*
 * Attaches a classic BPF filter so the kernel drops non-matching TCP
 * packets before they ever reach userspace, instead of every
 * unrelated TCP packet on the host costing us a syscall + copy +
 * parse-and-discard (a raw IPPROTO_TCP socket otherwise receives all
 * TCP traffic to the host, not just ours). Matches on a single TCP
 * port field; family must be the same one fd was opened with, since
 * v4/v6 raw sockets differ in whether the IP header is present in
 * what gets filtered (see rawsock_parse()'s doc comment). Best-effort:
 * logs a warning and leaves fd unfiltered (still correct, just
 * without the kernel-side fast path) if the kernel rejects it.
 */
void rawsock_filter_port(int fd, sa_family_t family, enum tcp_port_field field, uint16_t port);

#endif /* UDPMIMIC_RAWSOCK_H */
