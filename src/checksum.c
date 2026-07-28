/* checksum.c - RFC 1071 / RFC 2460 Internet checksums. */
#include "checksum.h"

/*
 * raw_sum() adds a byte buffer into a running one's-complement sum,
 * without folding or complementing. Safe to call repeatedly to sum
 * several concatenated buffers, as long as only the *last* buffer in
 * the chain has an odd length (true for all uses here: fixed-size
 * pseudo-header, fixed-size TCP header, then a variable-length
 * payload that is always the final segment).
 */
static uint32_t raw_sum(const void *data, size_t len, uint32_t sum)
{
	const uint16_t *p = data;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}
	if (len == 1)
		sum += *(const uint8_t *)p;

	return sum;
}

static uint16_t fold_sum(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

uint16_t inet_checksum(const void *data, size_t len, uint32_t init_sum)
{
	return fold_sum(raw_sum(data, len, init_sum));
}

/* TCP checksum = pseudo-header + TCP header (checksum field zeroed) + payload */
uint16_t tcp4_checksum(const struct iphdr *ip, const struct tcphdr *tcp,
			const uint8_t *payload, size_t payload_len)
{
	struct {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t zero;
		uint8_t proto;
		uint16_t tcp_len;
	} __attribute__((packed)) pseudo;
	struct tcphdr tmp;
	uint32_t sum;

	pseudo.saddr = ip->saddr;
	pseudo.daddr = ip->daddr;
	pseudo.zero = 0;
	pseudo.proto = IPPROTO_TCP;
	pseudo.tcp_len = htons((uint16_t)(sizeof(*tcp) + payload_len));

	tmp = *tcp;
	tmp.check = 0;

	sum = raw_sum(&pseudo, sizeof(pseudo), 0);
	sum = raw_sum(&tmp, sizeof(tmp), sum);
	if (payload_len)
		sum = raw_sum(payload, payload_len, sum);

	return fold_sum(sum);
}

/* RFC 2460 8.1: pseudo-header is src(16)+dst(16)+upper-layer length(4)+zero(3)+next-header(1). */
uint16_t tcp6_checksum(const struct in6_addr *src, const struct in6_addr *dst,
			const struct tcphdr *tcp, const uint8_t *payload,
			size_t payload_len)
{
	struct {
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t upper_len;
		uint8_t zero[3];
		uint8_t next_hdr;
	} __attribute__((packed)) pseudo;
	struct tcphdr tmp;
	uint32_t sum;

	pseudo.src = *src;
	pseudo.dst = *dst;
	pseudo.upper_len = htonl((uint32_t)(sizeof(*tcp) + payload_len));
	memset(pseudo.zero, 0, sizeof(pseudo.zero));
	pseudo.next_hdr = IPPROTO_TCP;

	tmp = *tcp;
	tmp.check = 0;

	sum = raw_sum(&pseudo, sizeof(pseudo), 0);
	sum = raw_sum(&tmp, sizeof(tmp), sum);
	if (payload_len)
		sum = raw_sum(payload, payload_len, sum);

	return fold_sum(sum);
}
