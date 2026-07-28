/*
 * server.c - fake-TCP listener, one session per client, each session
 * forwarding to its own UDP socket connected to the real backend.
 *
 * Address families: the raw socket(s) opened match cfg->listen_addr's
 * family. Binding to the IPv6 wildcard ([::]:port) additionally opens
 * a second, IPv4 raw socket so v4 and v6 clients share the same port
 * (the usual dual-stack idiom) — both feed the same session table,
 * distinguished by struct netaddr's family tag. The backend UDP
 * socket family always follows cfg->remote_addr, independent of which
 * family a given client arrived over.
 */
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "common.h"
#include "rawsock.h"
#include "session.h"

#define REAP_INTERVAL_SEC 5
#define RECV_BATCH_BUF    2048
#define MAX_RAW_FD        2

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

struct srv_ctx {
	const struct config *cfg;
	struct session_pool  pool;
	int raw_fd[MAX_RAW_FD];
	int n_raw_fd;
	int epoll_fd;
	uint16_t listen_port;
};

static int raw_fd_for(struct srv_ctx *ctx, sa_family_t family)
{
	int i;

	for (i = 0; i < ctx->n_raw_fd; i++) {
		/* raw_fd[0] always matches cfg->listen_addr's family; any
		 * extra fd (raw_fd[1]) is always the IPv4 dual-stack aux. */
		sa_family_t fd_family = (i == 0) ? ctx->cfg->listen_addr.family : AF_INET;

		if (fd_family == family)
			return ctx->raw_fd[i];
	}
	return -1;
}

static uint32_t rand_isn(void)
{
	uint32_t v;

	if (getrandom(&v, sizeof(v), 0) != sizeof(v))
		v = (uint32_t)(now_sec() ^ (long)&v);
	return v;
}

static int send_ctrl(struct srv_ctx *ctx, const struct session *s,
		      uint8_t flags, const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[RECV_BATCH_BUF];
	struct fake_tcp_hdr h = {
		.src = s->local,
		.dst = s->key,
		.seq = s->snd_nxt,
		.ack = s->rcv_nxt,
		.flags = flags,
		.window = 65535,
	};
	int fd = raw_fd_for(ctx, s->key.family);
	int len;

	h.src.port = ctx->listen_port;
	h.dst.port = s->key.port;

	if (fd < 0)
		return -1;

	len = rawsock_build(buf, sizeof(buf), &h, payload, payload_len);
	if (len < 0) {
		pr_warn("packet too big to build (%zu payload bytes)", payload_len);
		return -1;
	}
	return rawsock_send(fd, buf, (size_t)len, &s->key);
}

static void release_backend_fd(struct srv_ctx *ctx, struct session *s)
{
	if (s->remote_fd >= 0) {
		epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, s->remote_fd, NULL);
		close(s->remote_fd);
		s->remote_fd = -1;
	}
}

/* RST/FIN from the peer, or a locally-decided teardown: release now. */
static void close_session(struct srv_ctx *ctx, struct session *s)
{
	release_backend_fd(ctx, s);
	session_remove(&ctx->pool, s);
}

/* Called by session_reap_expired() right before it removes the node itself. */
static void on_expire(struct session *s, void *arg)
{
	struct srv_ctx *ctx = arg;
	char buf[64];

	pr_debug("session %s expired", netaddr_str(&s->key, buf, sizeof(buf)));
	send_ctrl(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
	release_backend_fd(ctx, s);
}

static int open_backend_socket(struct srv_ctx *ctx)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	int fd = socket(ctx->cfg->remote_addr.family, SOCK_DGRAM | SOCK_NONBLOCK, 0);

	if (fd < 0) {
		pr_err("socket(backend UDP): %s", strerror(errno));
		return -1;
	}
	netaddr_to_sockaddr(&ctx->cfg->remote_addr, &ss, &sl);
	if (connect(fd, (const struct sockaddr *)&ss, sl) < 0) {
		pr_err("connect(backend UDP): %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static void handle_new_client(struct srv_ctx *ctx, const struct fake_tcp_hdr *h,
			       const uint8_t *payload, size_t payload_len)
{
	struct session *s;
	struct epoll_event ev;
	char buf[64];

	s = session_create(&ctx->pool, &h->src);
	if (!s) {
		pr_warn("session pool exhausted (max=%d), dropping new client",
			ctx->cfg->max_sessions);
		return;
	}

	if (h->src.family == AF_INET6) {
		/* IPv6 raw sockets never hand us the packet's own IPv6 header
		 * (see rawsock.h), so h->dst.ip is unset here; ask the kernel
		 * which of our addresses routes back to this client instead. */
		if (netaddr_route_lookup(&h->src, &s->local) < 0) {
			pr_warn("route lookup for reply address failed: %s", strerror(errno));
			session_remove(&ctx->pool, s);
			return;
		}
		s->local.port = 0;
	} else {
		s->local = h->dst; /* IPv4 raw sockets give us this for free */
	}
	/* the SYN itself consumes one sequence number; a client may combine
	 * SYN+PSH to piggyback its first datagram on the opening segment */
	s->rcv_nxt = h->seq + 1 + (uint32_t)payload_len;
	s->snd_nxt = rand_isn();
	s->state = SESS_SYN_RCVD;

	s->remote_fd = open_backend_socket(ctx);
	if (s->remote_fd < 0) {
		session_remove(&ctx->pool, s);
		return;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = s;
	if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, s->remote_fd, &ev) < 0) {
		pr_err("epoll_ctl ADD backend fd: %s", strerror(errno));
		close_session(ctx, s);
		return;
	}

	if (payload_len && send(s->remote_fd, payload, payload_len, 0) < 0)
		pr_warn("forward to backend failed: %s", strerror(errno));

	send_ctrl(ctx, s, TCPF_SYN | TCPF_ACK, NULL, 0);
	s->snd_nxt++; /* SYN consumes one sequence number */

	pr_debug("new session %s", netaddr_str(&h->src, buf, sizeof(buf)));
}

static void handle_client_packet(struct srv_ctx *ctx, struct session *s,
				  const struct fake_tcp_hdr *h,
				  const uint8_t *payload, size_t payload_len)
{
	session_touch(&ctx->pool, s);

	if (h->flags & (TCPF_RST | TCPF_FIN)) {
		char buf[64];

		pr_debug("session %s closed by peer", netaddr_str(&s->key, buf, sizeof(buf)));
		close_session(ctx, s);
		return;
	}

	if (s->state == SESS_SYN_RCVD && (h->flags & TCPF_ACK) && !payload_len) {
		s->state = SESS_ESTABLISHED;
		return;
	}
	if (s->state == SESS_SYN_RCVD)
		s->state = SESS_ESTABLISHED; /* data piggybacked on final ACK */

	if (!payload_len)
		return; /* bare keepalive ACK, nothing to forward */

	if (send(s->remote_fd, payload, payload_len, 0) < 0)
		pr_warn("forward to backend failed: %s", strerror(errno));

	s->rcv_nxt = h->seq + (uint32_t)payload_len;
	send_ctrl(ctx, s, TCPF_ACK, NULL, 0);
}

static void handle_raw_readable(struct srv_ctx *ctx, int fd, sa_family_t family)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		struct sockaddr_storage from;
		socklen_t from_len = sizeof(from);
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
		struct fake_tcp_hdr h;
		struct netaddr peer;
		const uint8_t *payload;
		size_t payload_len;
		struct session *s;

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("raw recv: %s", strerror(errno));
			return;
		}
		if (rawsock_parse(family, buf, (size_t)n, &h, &payload, &payload_len) < 0)
			continue;
		/* Authoritative source address from the kernel; the only way
		 * to get it at all for IPv6 (see rawsock.h), and no less
		 * correct than the IPv4 header parse for v4. TCP port stays
		 * as parsed from the TCP header -- raw sockets have no port
		 * concept, so recvfrom()'s peer port is meaningless/unset. */
		netaddr_from_sockaddr((struct sockaddr *)&from, &peer);
		h.src.family = peer.family;
		h.src.ip = peer.ip;

		if (h.dst.port != ctx->listen_port)
			continue;
		/*
		 * Enforce a specific bind address only for IPv4, and only
		 * when the fd's family matches what the user configured
		 * (the IPv4 dual-stack aux socket always accepts any v4
		 * dest, since there's no user-specified v4 address to
		 * compare). IPv6 has no destination address available here
		 * at all (see rawsock.h) -- resolving it would cost a
		 * route lookup per packet, not just per session, so we
		 * simply don't filter on it; port matching is still the
		 * primary discriminator and applies to both families.
		 */
		if (family == AF_INET && h.dst.family == ctx->cfg->listen_addr.family &&
		    !netaddr_is_any(&ctx->cfg->listen_addr) &&
		    !netaddr_equal_addr(&h.dst, &ctx->cfg->listen_addr))
			continue;

		s = session_lookup(&ctx->pool, &h.src);
		if (!s) {
			if ((h.flags & TCPF_SYN) && !(h.flags & TCPF_ACK))
				handle_new_client(ctx, &h, payload, payload_len);
			continue;
		}
		handle_client_packet(ctx, s, &h, payload, payload_len);
	}
}

static void handle_backend_readable(struct srv_ctx *ctx, struct session *s)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		ssize_t n = recv(s->remote_fd, buf, sizeof(buf), 0);

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("backend recv: %s", strerror(errno));
			return;
		}
		if (n == 0)
			continue;

		send_ctrl(ctx, s, TCPF_PSH | TCPF_ACK, buf, (size_t)n);
		s->snd_nxt += (uint32_t)n;
		session_touch(&ctx->pool, s);
	}
}

static void shutdown_all_sessions(struct srv_ctx *ctx)
{
	struct list_head *pos, *n;

	for (pos = ctx->pool.lru.next, n = pos->next; pos != &ctx->pool.lru;
	     pos = n, n = pos->next) {
		struct session *s = list_entry(pos, struct session, lru);

		send_ctrl(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
		close_session(ctx, s);
	}
}

int server_main(const struct config *cfg)
{
	struct srv_ctx ctx;
	struct epoll_event ev, events[64];
	int timer_fd;
	int i;
	struct itimerspec its = {
		.it_interval = { .tv_sec = REAP_INTERVAL_SEC },
		.it_value = { .tv_sec = REAP_INTERVAL_SEC },
	};
	char abuf[64], rbuf[64];

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;
	ctx.listen_port = cfg->listen_addr.port;

	if (session_pool_init(&ctx.pool, (size_t)cfg->max_sessions) < 0)
		return 1;

	ctx.raw_fd[0] = rawsock_open(cfg->listen_addr.family);
	if (ctx.raw_fd[0] < 0)
		return 1;
	rawsock_filter_port(ctx.raw_fd[0], cfg->listen_addr.family, TCP_PORT_DST, ctx.listen_port);
	ctx.n_raw_fd = 1;

	if (cfg->listen_addr.family == AF_INET6 && netaddr_is_any(&cfg->listen_addr)) {
		ctx.raw_fd[1] = rawsock_open(AF_INET);
		if (ctx.raw_fd[1] < 0)
			return 1;
		rawsock_filter_port(ctx.raw_fd[1], AF_INET, TCP_PORT_DST, ctx.listen_port);
		ctx.n_raw_fd = 2;
	}

	ctx.epoll_fd = epoll_create1(0);
	if (ctx.epoll_fd < 0) {
		pr_err("epoll_create1: %s", strerror(errno));
		return 1;
	}

	timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timer_fd < 0 || timerfd_settime(timer_fd, 0, &its, NULL) < 0) {
		pr_err("timerfd setup: %s", strerror(errno));
		return 1;
	}

	for (i = 0; i < ctx.n_raw_fd; i++) {
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLET;
		ev.data.ptr = &ctx.raw_fd[i]; /* distinct sentinel per raw fd */
		epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.raw_fd[i], &ev);
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = &timer_fd; /* distinct non-NULL sentinel value */
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	pr_info("server listening on fake-tcp %s%s, backend %s, max_sessions=%d",
		netaddr_str(&cfg->listen_addr, abuf, sizeof(abuf)),
		ctx.n_raw_fd > 1 ? " (dual-stack, also accepting IPv4)" : "",
		netaddr_str(&cfg->remote_addr, rbuf, sizeof(rbuf)), cfg->max_sessions);

	while (!g_stop) {
		int n = epoll_wait(ctx.epoll_fd, events, 64, -1);
		int j, k;
		int matched;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			pr_err("epoll_wait: %s", strerror(errno));
			break;
		}

		for (j = 0; j < n; j++) {
			matched = 0;
			for (k = 0; k < ctx.n_raw_fd; k++) {
				if (events[j].data.ptr == &ctx.raw_fd[k]) {
					sa_family_t family = (k == 0) ? cfg->listen_addr.family : AF_INET;

					handle_raw_readable(&ctx, ctx.raw_fd[k], family);
					matched = 1;
					break;
				}
			}
			if (matched)
				continue;

			if (events[j].data.ptr == &timer_fd) {
				uint64_t exp;
				ssize_t r = read(timer_fd, &exp, sizeof(exp));

				(void)r;
				session_reap_expired(&ctx.pool, cfg->timeout_sec,
						      on_expire, &ctx);
			} else {
				handle_backend_readable(&ctx, events[j].data.ptr);
			}
		}
	}

	pr_info("shutting down, closing %zu session(s)", ctx.pool.count);
	shutdown_all_sessions(&ctx);
	close(timer_fd);
	for (i = 0; i < ctx.n_raw_fd; i++)
		close(ctx.raw_fd[i]);
	close(ctx.epoll_fd);
	session_pool_destroy(&ctx.pool);
	return 0;
}
