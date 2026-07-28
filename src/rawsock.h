/* rawsock.h - fake-TCP framing over an IP_HDRINCL raw socket. */
#ifndef UDPMIMIC_RAWSOCK_H
#define UDPMIMIC_RAWSOCK_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* Flags we actually use; kept as plain bits so callers can OR them. */
#define TCPF_SYN 0x01
#define TCPF_ACK 0x02
#define TCPF_PSH 0x04
#define TCPF_FIN 0x08
#define TCPF_RST 0x10

struct fake_tcp_hdr {
	uint32_t saddr;		/* network byte order */
	uint32_t daddr;
	uint16_t sport;		/* host byte order */
	uint16_t dport;
	uint32_t seq;		/* host byte order */
	uint32_t ack;
	uint8_t  flags;
	uint16_t window;
};

/* Create the shared raw socket used for both sending and receiving. */
int rawsock_open(void);

/*
 * Build one IPv4+TCP packet with the given payload into buf (caller
 * owns buf, must be at least UDPMIMIC_MAX_PKT bytes). Returns the
 * total packet length, or -1 on overflow.
 */
int rawsock_build(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		   const uint8_t *payload, size_t payload_len);

/* sendto() a pre-built packet produced by rawsock_build(). */
int rawsock_send(int fd, const uint8_t *pkt, size_t pkt_len, uint32_t daddr);

/*
 * Parse an inbound raw packet. On success returns 0, fills *h and
 * points payload/payload_len at the TCP payload inside buf (no
 * copy). Non-TCP or truncated packets return -1.
 */
int rawsock_parse(const uint8_t *buf, size_t len, struct fake_tcp_hdr *h,
		   const uint8_t **payload, size_t *payload_len);

#endif /* UDPMIMIC_RAWSOCK_H */
