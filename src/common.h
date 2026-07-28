/* common.h - shared types, logging, small helpers. */
#ifndef UDPMIMIC_COMMON_H
#define UDPMIMIC_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

extern int g_verbose;

enum run_mode {
	MODE_SERVER,
	MODE_CLIENT,
};

struct config {
	enum run_mode mode;
	struct sockaddr_in listen_addr; /* server: fake-tcp listen; client: local UDP bind */
	struct sockaddr_in remote_addr; /* server: real UDP backend; client: udpmimic server */
	int max_sessions;
	int timeout_sec;
	int keepalive_sec;
};

/* Parses "ip:port" (ip may be omitted -> 0.0.0.0) into *out. Returns -1 on error. */
int parse_addr(const char *s, struct sockaddr_in *out);

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
