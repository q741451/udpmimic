/* checksum.h - Internet checksum helpers for hand-built IPv4/TCP headers. */
#ifndef UDPMIMIC_CHECKSUM_H
#define UDPMIMIC_CHECKSUM_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

uint16_t inet_checksum(const void *data, size_t len, uint32_t init_sum);

uint16_t tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp,
		       const uint8_t *payload, size_t payload_len);

#endif /* UDPMIMIC_CHECKSUM_H */
