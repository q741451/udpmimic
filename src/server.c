/*
 * server.c - fake-TCP listener, one session per client, each session
 * forwarding to its own UDP socket connected to the real backend.
 */
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "rawsock.h"
#include "session.h"

#define REAP_INTERVAL_SEC 5
#define RECV_BATCH_BUF    2048

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

struct srv_ctx {
	const struct config *cfg;
	struct session_pool  pool;
	int raw_fd;
	int epoll_fd;
	uint16_t listen_port;
};

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
		.saddr = s->local_ip,
		.daddr = s->key_ip,
		.sport = ctx->listen_port,
		.dport = s->key_port,
		.seq = s->snd_nxt,
		.ack = s->rcv_nxt,
		.flags = flags,
		.window = 65535,
	};
	int len = rawsock_build(buf, sizeof(buf), &h, payload, payload_len);

	if (len < 0) {
		pr_warn("packet too big to build (%zu payload bytes)", payload_len);
		return -1;
	}
	return rawsock_send(ctx->raw_fd, buf, (size_t)len, s->key_ip);
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

	pr_debug("session %s:%u expired", inet_ntoa(*(struct in_addr *)&s->key_ip),
		  s->key_port);
	send_ctrl(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
	release_backend_fd(ctx, s);
}

static int open_backend_socket(struct srv_ctx *ctx)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);

	if (fd < 0) {
		pr_err("socket(backend UDP): %s", strerror(errno));
		return -1;
	}
	if (connect(fd, (const struct sockaddr *)&ctx->cfg->remote_addr,
		    sizeof(ctx->cfg->remote_addr)) < 0) {
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

	s = session_create(&ctx->pool, h->saddr, h->sport);
	if (!s) {
		pr_warn("session pool exhausted (max=%d), dropping new client",
			ctx->cfg->max_sessions);
		return;
	}

	s->local_ip = h->daddr;
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

	pr_debug("new session %s:%u", inet_ntoa(*(struct in_addr *)&h->saddr), h->sport);
}

static void handle_client_packet(struct srv_ctx *ctx, struct session *s,
				  const struct fake_tcp_hdr *h,
				  const uint8_t *payload, size_t payload_len)
{
	session_touch(&ctx->pool, s);

	if (h->flags & (TCPF_RST | TCPF_FIN)) {
		pr_debug("session %s:%u closed by peer", inet_ntoa(*(struct in_addr *)&s->key_ip),
			  s->key_port);
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

static void handle_raw_readable(struct srv_ctx *ctx)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		ssize_t n = recv(ctx->raw_fd, buf, sizeof(buf), 0);
		struct fake_tcp_hdr h;
		const uint8_t *payload;
		size_t payload_len;
		struct session *s;

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("raw recv: %s", strerror(errno));
			return;
		}
		if (rawsock_parse(buf, (size_t)n, &h, &payload, &payload_len) < 0)
			continue;
		if (h.dport != ctx->listen_port)
			continue;
		if (ctx->cfg->listen_addr.sin_addr.s_addr != INADDR_ANY &&
		    h.daddr != ctx->cfg->listen_addr.sin_addr.s_addr)
			continue;

		s = session_lookup(&ctx->pool, h.saddr, h.sport);
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
	struct itimerspec its = {
		.it_interval = { .tv_sec = REAP_INTERVAL_SEC },
		.it_value = { .tv_sec = REAP_INTERVAL_SEC },
	};

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;
	ctx.listen_port = ntohs(cfg->listen_addr.sin_port);

	if (session_pool_init(&ctx.pool, (size_t)cfg->max_sessions) < 0)
		return 1;

	ctx.raw_fd = rawsock_open();
	if (ctx.raw_fd < 0)
		return 1;

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

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = NULL;
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.raw_fd, &ev);

	ev.data.ptr = &timer_fd; /* distinct non-NULL sentinel value */
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	pr_info("server listening on fake-tcp port %u, backend %s:%u, max_sessions=%d",
		ctx.listen_port, inet_ntoa(cfg->remote_addr.sin_addr),
		ntohs(cfg->remote_addr.sin_port), cfg->max_sessions);

	while (!g_stop) {
		int n = epoll_wait(ctx.epoll_fd, events, 64, -1);
		int i;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			pr_err("epoll_wait: %s", strerror(errno));
			break;
		}

		for (i = 0; i < n; i++) {
			if (events[i].data.ptr == NULL) {
				handle_raw_readable(&ctx);
			} else if (events[i].data.ptr == &timer_fd) {
				uint64_t exp;
				ssize_t r = read(timer_fd, &exp, sizeof(exp));
				(void)r;
				session_reap_expired(&ctx.pool, cfg->timeout_sec,
						      on_expire, &ctx);
			} else {
				handle_backend_readable(&ctx, events[i].data.ptr);
			}
		}
	}

	pr_info("shutting down, closing %zu session(s)", ctx.pool.count);
	shutdown_all_sessions(&ctx);
	close(timer_fd);
	close(ctx.raw_fd);
	close(ctx.epoll_fd);
	session_pool_destroy(&ctx.pool);
	return 0;
}
