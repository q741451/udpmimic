/* common.c - shared globals and address helpers. */
#include <unistd.h>
#include <arpa/inet.h>

#include "common.h"

int g_verbose;

int parse_addr(const char *s, struct netaddr *out)
{
	char buf[128];
	char *ip_part, *port_part;
	long port;

	memset(out, 0, sizeof(*out));
	if (strlen(s) >= sizeof(buf))
		return -1;
	memcpy(buf, s, strlen(s) + 1);

	if (buf[0] == '[') {
		char *close = strchr(buf, ']');

		if (!close || close[1] != ':')
			return -1;
		*close = '\0';
		ip_part = buf + 1;
		port_part = close + 2;
		out->family = AF_INET6;
		if (inet_pton(AF_INET6, ip_part, &out->ip.v6) != 1)
			return -1;
	} else {
		char *colon = strrchr(buf, ':');

		if (!colon)
			return -1;
		*colon = '\0';
		ip_part = buf;
		port_part = colon + 1;
		out->family = AF_INET;
		if (inet_pton(AF_INET, ip_part, &out->ip.v4) != 1)
			return -1;
	}

	errno = 0;
	port = strtol(port_part, NULL, 10);
	if (errno || port <= 0 || port > 65535)
		return -1;

	out->port = (uint16_t)port;
	return 0;
}

size_t netaddr_len(sa_family_t family)
{
	return family == AF_INET6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
}

int netaddr_equal_addr(const struct netaddr *a, const struct netaddr *b)
{
	if (a->family != b->family)
		return 0;
	return memcmp(&a->ip, &b->ip, netaddr_len(a->family)) == 0;
}

int netaddr_equal(const struct netaddr *a, const struct netaddr *b)
{
	return a->port == b->port && netaddr_equal_addr(a, b);
}

int netaddr_is_any(const struct netaddr *a)
{
	if (a->family == AF_INET6)
		return IN6_IS_ADDR_UNSPECIFIED(&a->ip.v6);
	return a->ip.v4.s_addr == htonl(INADDR_ANY);
}

size_t netaddr_hash(size_t nbuckets, const struct netaddr *a)
{
	uint64_t h = 1469598103934665603ULL; /* FNV-1a offset basis */
	const uint8_t *p = (const uint8_t *)&a->ip;
	size_t n = netaddr_len(a->family);
	size_t i;

	h = (h ^ (uint64_t)a->family) * 1099511628211ULL;
	h = (h ^ (uint64_t)a->port) * 1099511628211ULL;
	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ULL;

	h *= 0x9E3779B97F4A7C15ULL; /* final Fibonacci mix for better bit spread */
	return (size_t)(h >> 48) & (nbuckets - 1);
}

void netaddr_to_sockaddr(const struct netaddr *a, struct sockaddr_storage *ss, socklen_t *len)
{
	memset(ss, 0, sizeof(*ss));
	if (a->family == AF_INET6) {
		struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;

		s6->sin6_family = AF_INET6;
		s6->sin6_port = htons(a->port);
		s6->sin6_addr = a->ip.v6;
		*len = sizeof(*s6);
	} else {
		struct sockaddr_in *s4 = (struct sockaddr_in *)ss;

		s4->sin_family = AF_INET;
		s4->sin_port = htons(a->port);
		s4->sin_addr = a->ip.v4;
		*len = sizeof(*s4);
	}
}

void netaddr_from_sockaddr(const struct sockaddr *sa, struct netaddr *out)
{
	memset(out, 0, sizeof(*out));
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;

		out->family = AF_INET6;
		out->ip.v6 = s6->sin6_addr;
		out->port = ntohs(s6->sin6_port);
	} else {
		const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;

		out->family = AF_INET;
		out->ip.v4 = s4->sin_addr;
		out->port = ntohs(s4->sin_port);
	}
}

int netaddr_route_lookup(const struct netaddr *peer, struct netaddr *out)
{
	int fd = socket(peer->family, SOCK_DGRAM, 0);
	struct sockaddr_storage remote, local;
	socklen_t rlen, llen = sizeof(local);
	int ret = -1;

	if (fd < 0)
		return -1;

	netaddr_to_sockaddr(peer, &remote, &rlen);
	if (connect(fd, (struct sockaddr *)&remote, rlen) == 0 &&
	    getsockname(fd, (struct sockaddr *)&local, &llen) == 0) {
		netaddr_from_sockaddr((struct sockaddr *)&local, out);
		ret = 0;
	}
	close(fd);
	return ret;
}

const char *netaddr_str(const struct netaddr *a, char *buf, size_t buflen)
{
	char ipbuf[INET6_ADDRSTRLEN];

	inet_ntop(a->family, &a->ip, ipbuf, sizeof(ipbuf));
	if (a->family == AF_INET6)
		snprintf(buf, buflen, "[%s]:%u", ipbuf, a->port);
	else
		snprintf(buf, buflen, "%s:%u", ipbuf, a->port);
	return buf;
}
