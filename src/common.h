/* common.h - shared types, logging, small helpers. */
#ifndef UDPMIMIC_COMMON_H
#define UDPMIMIC_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern int g_verbose;

enum run_mode {
	MODE_SERVER,
	MODE_CLIENT,
};

/*
 * Address-family-agnostic endpoint: family selects which member of ip
 * is meaningful. Deliberately NOT a sockaddr_in/in6 union so it stays
 * a flat, easily hashable/comparable value (port kept in host order,
 * same convention as struct fake_tcp_hdr).
 */
struct netaddr {
	sa_family_t family;	/* AF_INET or AF_INET6 */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} ip;
	uint16_t port;		/* host byte order */
};

struct config {
	enum run_mode mode;
	struct netaddr listen_addr; /* server: fake-tcp listen; client: local UDP bind */
	struct netaddr remote_addr; /* server: real UDP backend; client: udpmimic server */
	int max_sessions;
	int timeout_sec;
	int keepalive_sec;
};

/* Parses "ip:port" or "[ipv6]:port" into *out. Returns -1 on error. */
int parse_addr(const char *s, struct netaddr *out);

/* Number of meaningful address bytes for a->family (4 or 16). */
size_t netaddr_len(sa_family_t family);

/* family + ip + port all equal. */
int netaddr_equal(const struct netaddr *a, const struct netaddr *b);

/* family + ip equal, port ignored (for filtering by destination address). */
int netaddr_equal_addr(const struct netaddr *a, const struct netaddr *b);

/* 0.0.0.0 or ::. */
int netaddr_is_any(const struct netaddr *a);

/* Fibonacci-mixed hash over family+ip(family-appropriate length)+port,
 * result in [0, nbuckets). nbuckets must be a power of two. */
size_t netaddr_hash(size_t nbuckets, const struct netaddr *a);

void netaddr_to_sockaddr(const struct netaddr *a, struct sockaddr_storage *ss, socklen_t *len);
void netaddr_from_sockaddr(const struct sockaddr *sa, struct netaddr *out);

/*
 * connect()+getsockname() trick: asks the kernel which local address
 * it would route a packet to `peer` from, without sending anything.
 * Used both for the client's own outbound address and, on IPv6, for
 * the server to recover which of its addresses a client's packet
 * arrived on (IPv6 raw sockets don't expose that on receive the way
 * IPv4 ones do -- see rawsock.h). Returns -1 on failure.
 */
int netaddr_route_lookup(const struct netaddr *peer, struct netaddr *out);

/* Formats into caller-provided buf (e.g. "1.2.3.4:5678" / "[::1]:5678"), returns buf. */
const char *netaddr_str(const struct netaddr *a, char *buf, size_t buflen);

#define pr_err(fmt, ...) \
	fprintf(stderr, "[err] " fmt "\n", ##__VA_ARGS__)

#define pr_warn(fmt, ...) \
	fprintf(stderr, "[warn] " fmt "\n", ##__VA_ARGS__)

#define pr_info(fmt, ...) \
	fprintf(stderr, "[info] " fmt "\n", ##__VA_ARGS__)

#define pr_debug(fmt, ...) \
	do { \
		if (g_verbose) \
			fprintf(stderr, "[dbg] " fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define UDPMIMIC_MAX_PKT 1600U	/* enough for typical VPN MTU + hdrs, no jumbo */

static inline time_t now_sec(void)
{
	return time(NULL);
}

#endif /* UDPMIMIC_COMMON_H */
