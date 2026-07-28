/* main.c - CLI parsing, dispatches to server_main()/client_main(). */
#include <unistd.h>

#include "common.h"

int server_main(const struct config *cfg);
int client_main(const struct config *cfg);

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage:\n"
		"  %s -s -l <listen_ip:port> -r <backend_ip:port> [-n max_sessions] [-t timeout_sec] [-v]\n"
		"  %s -c -l <local_udp_ip:port> -r <server_ip:port> [-n max_sessions] [-k keepalive_sec] [-v]\n"
		"\n"
		"addresses: \"ip:port\" for IPv4, \"[ip6]:port\" for IPv6 (e.g. \"[::]:8390\").\n"
		"  -s -l [::]:PORT also accepts IPv4 clients on the same port (dual-stack).\n",
		prog, prog);
}

int main(int argc, char **argv)
{
	struct config cfg;
	int opt;
	int have_mode = 0, have_l = 0, have_r = 0;

	memset(&cfg, 0, sizeof(cfg));
	cfg.max_sessions = -1; /* fill role-specific default after parsing */
	cfg.timeout_sec = 120;
	cfg.keepalive_sec = 20;

	while ((opt = getopt(argc, argv, "scl:r:n:t:k:vh")) != -1) {
		switch (opt) {
		case 's':
			cfg.mode = MODE_SERVER;
			have_mode = 1;
			break;
		case 'c':
			cfg.mode = MODE_CLIENT;
			have_mode = 1;
			break;
		case 'l':
			if (parse_addr(optarg, &cfg.listen_addr) < 0) {
				pr_err("bad -l address: %s", optarg);
				return 1;
			}
			have_l = 1;
			break;
		case 'r':
			if (parse_addr(optarg, &cfg.remote_addr) < 0) {
				pr_err("bad -r address: %s", optarg);
				return 1;
			}
			have_r = 1;
			break;
		case 'n':
			cfg.max_sessions = atoi(optarg);
			break;
		case 't':
			cfg.timeout_sec = atoi(optarg);
			break;
		case 'k':
			cfg.keepalive_sec = atoi(optarg);
			break;
		case 'v':
			g_verbose = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!have_mode || !have_l || !have_r) {
		usage(argv[0]);
		return 1;
	}

	if (cfg.max_sessions <= 0)
		cfg.max_sessions = (cfg.mode == MODE_SERVER) ? 4096 : 256;

	return cfg.mode == MODE_SERVER ? server_main(&cfg) : client_main(&cfg);
}
