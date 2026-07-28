/* common.c - shared globals and small helpers. */
#include <arpa/inet.h>

#include "common.h"

int g_verbose;

int parse_addr(const char *s, struct sockaddr_in *out)
{
	char buf[64];
	char *colon;
	const char *ip_part;
	const char *port_part;
	long port;

	if (strlen(s) >= sizeof(buf))
		return -1;
	memcpy(buf, s, strlen(s) + 1);

	colon = strrchr(buf, ':');
	if (!colon || colon == buf + strlen(buf) - 1)
		return -1;

	*colon = '\0';
	ip_part = buf;
	port_part = colon + 1;

	memset(out, 0, sizeof(*out));
	out->sin_family = AF_INET;

	if (inet_pton(AF_INET, ip_part, &out->sin_addr) != 1)
		return -1;

	errno = 0;
	port = strtol(port_part, NULL, 10);
	if (errno || port <= 0 || port > 65535)
		return -1;

	out->sin_port = htons((uint16_t)port);
	return 0;
}
