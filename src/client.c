/*
 * client.c - relays one or more local UDP peers to a single remote
 * udpmimic server, one independent fake-TCP "connection" per local
 * peer so the server's existing multi-session logic just sees more
 * clients.
 *
 * Address families: the outer raw socket's family follows
 * cfg->remote_addr (there is only one remote server, of one family).
 * The local UDP socket's family follows cfg->listen_addr independently
 * -- e.g. a v6-only local app behind a client tunneling over v4 to the
 * server, or vice versa, both work.
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

#define KEEPALIVE_TICK_SEC 1
#define RECV_BATCH_BUF     2048
#define PORT_BASE          20000
#define PORT_RANGE         (65535 - PORT_BASE)

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

/* Secondary index: local UDP peer address -> session, chained via
 * s->pnext. Reuses the same netaddr_hash()/netaddr_equal() as the
 * primary table in session.c, just against a different key field. */
struct peer_index {
	struct session **buckets;
	size_t           nbuckets;
};

static int peer_index_init(struct peer_index *idx, size_t capacity)
{
	size_t nb = 16;

	while (nb < capacity * 2)
		nb <<= 1;
	idx->nbuckets = nb;
	idx->buckets = calloc(nb, sizeof(*idx->buckets));
	return idx->buckets ? 0 : -1;
}

static struct session *peer_index_lookup(struct peer_index *idx, const struct netaddr *peer)
{
	struct session *s = idx->buckets[netaddr_hash(idx->nbuckets, peer)];

	while (s) {
		if (netaddr_equal(&s->inner_peer, peer))
			return s;
		s = s->pnext;
	}
	return NULL;
}

static void peer_index_insert(struct peer_index *idx, struct session *s)
{
	size_t b = netaddr_hash(idx->nbuckets, &s->inner_peer);

	s->pnext = idx->buckets[b];
	idx->buckets[b] = s;
}

static void peer_index_remove(struct peer_index *idx, struct session *s)
{
	size_t b = netaddr_hash(idx->nbuckets, &s->inner_peer);
	struct session **pp = &idx->buckets[b];

	while (*pp) {
		if (*pp == s) {
			*pp = s->pnext;
			return;
		}
		pp = &(*pp)->pnext;
	}
}

struct cli_ctx {
	const struct config *cfg;
	struct session_pool  pool;
	struct peer_index    peers;
	int raw_fd;
	int local_fd;
	int epoll_fd;
	struct netaddr local_addr;	/* our outbound interface addr, family = remote's */
	uint16_t next_port;
};

static uint32_t rand_isn(void)
{
	uint32_t v;

	if (getrandom(&v, sizeof(v), 0) != sizeof(v))
		v = (uint32_t)(now_sec() ^ (long)&v);
	return v;
}

static uint16_t alloc_port(struct cli_ctx *ctx)
{
	uint16_t tries;
	struct netaddr key = { .family = ctx->cfg->remote_addr.family };

	for (tries = 0; tries < PORT_RANGE; tries++) {
		key.port = PORT_BASE + ctx->next_port;
		ctx->next_port = (ctx->next_port + 1) % PORT_RANGE;
		if (!session_lookup(&ctx->pool, &key))
			return key.port;
	}
	return 0; /* exhausted */
}

static int send_pkt(struct cli_ctx *ctx, const struct session *s, uint8_t flags,
		     const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[RECV_BATCH_BUF];
	struct fake_tcp_hdr h = {
		.src = s->local,
		.dst = ctx->cfg->remote_addr,
		.seq = s->snd_nxt,
		.ack = s->rcv_nxt,
		.flags = flags,
		.window = 65535,
	};
	int len;

	h.src.port = s->key.port;

	len = rawsock_build(buf, sizeof(buf), &h, payload, payload_len);
	if (len < 0) {
		pr_warn("packet too big to build (%zu payload bytes)", payload_len);
		return -1;
	}
	return rawsock_send(ctx->raw_fd, buf, (size_t)len, &ctx->cfg->remote_addr);
}

static void close_session(struct cli_ctx *ctx, struct session *s)
{
	peer_index_remove(&ctx->peers, s);
	session_remove(&ctx->pool, s);
}

static void on_expire(struct session *s, void *arg)
{
	struct cli_ctx *ctx = arg;

	pr_debug("local session port=%u expired", s->key.port);
	send_pkt(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
	peer_index_remove(&ctx->peers, s);
}

static void handle_local_readable(struct cli_ctx *ctx)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		struct sockaddr_storage ss;
		struct netaddr peer;
		socklen_t peer_len = sizeof(ss);
		ssize_t n = recvfrom(ctx->local_fd, buf, sizeof(buf), 0,
				      (struct sockaddr *)&ss, &peer_len);
		struct session *s;
		uint16_t port;
		char abuf[64];

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("local recv: %s", strerror(errno));
			return;
		}
		netaddr_from_sockaddr((struct sockaddr *)&ss, &peer);

		s = peer_index_lookup(&ctx->peers, &peer);
		if (s) {
			session_touch(&ctx->pool, s);
			if (s->state != SESS_ESTABLISHED)
				continue; /* handshake in flight; drop like any lost UDP packet */
			send_pkt(ctx, s, TCPF_PSH | TCPF_ACK, buf, (size_t)n);
			s->snd_nxt += (uint32_t)n;
			continue;
		}

		port = alloc_port(ctx);
		if (!port) {
			pr_warn("outer port space exhausted, dropping new local peer");
			continue;
		}
		{
			struct netaddr key = { .family = ctx->cfg->remote_addr.family, .port = port };

			s = session_create(&ctx->pool, &key);
		}
		if (!s) {
			pr_warn("session pool exhausted (max=%d), dropping new local peer",
				ctx->cfg->max_sessions);
			continue;
		}
		s->inner_peer = peer;
		s->local = ctx->local_addr;
		s->snd_nxt = rand_isn();
		s->state = SESS_SYN_SENT;
		peer_index_insert(&ctx->peers, s);

		/* Combine SYN with the first payload: SYN occupies seq, the
		 * data bytes start right after it, exactly like a normal
		 * TCP Fast Open-style opening segment. Saves a round trip
		 * and avoids buffering the first datagram. */
		send_pkt(ctx, s, TCPF_SYN | TCPF_PSH, buf, (size_t)n);
		s->snd_nxt += 1 + (uint32_t)n;

		pr_debug("new local session peer=%s port=%u",
			  netaddr_str(&peer, abuf, sizeof(abuf)), port);
	}
}

static void handle_raw_readable(struct cli_ctx *ctx)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		struct sockaddr_storage from;
		socklen_t from_len = sizeof(from);
		ssize_t n = recvfrom(ctx->raw_fd, buf, sizeof(buf), 0,
				      (struct sockaddr *)&from, &from_len);
		struct fake_tcp_hdr h;
		struct netaddr peer;
		const uint8_t *payload;
		size_t payload_len;
		struct session *s;
		struct netaddr key;

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("raw recv: %s", strerror(errno));
			return;
		}
		if (rawsock_parse(ctx->cfg->remote_addr.family, buf, (size_t)n, &h,
				   &payload, &payload_len) < 0)
			continue;
		/* Authoritative source address from the kernel -- the only
		 * way to get it at all for IPv6 (see rawsock.h). TCP port
		 * stays as parsed from the TCP header. */
		netaddr_from_sockaddr((struct sockaddr *)&from, &peer);
		h.src.family = peer.family;
		h.src.ip = peer.ip;

		if (!netaddr_equal(&h.src, &ctx->cfg->remote_addr))
			continue; /* raw socket sees all TCP on the host; filter tightly */

		memset(&key, 0, sizeof(key));
		key.family = ctx->cfg->remote_addr.family;
		key.port = h.dst.port;

		s = session_lookup(&ctx->pool, &key);
		if (!s)
			continue;

		session_touch(&ctx->pool, s);

		if (h.flags & (TCPF_RST | TCPF_FIN)) {
			pr_debug("session port=%u closed by peer", s->key.port);
			close_session(ctx, s);
			continue;
		}

		if (s->state == SESS_SYN_SENT && (h.flags & TCPF_SYN) && (h.flags & TCPF_ACK)) {
			s->rcv_nxt = h.seq + 1;
			s->state = SESS_ESTABLISHED;
			send_pkt(ctx, s, TCPF_ACK, NULL, 0);
			if (!payload_len)
				continue;
		}

		if (!payload_len)
			continue;

		{
			struct sockaddr_storage ss;
			socklen_t sl;

			netaddr_to_sockaddr(&s->inner_peer, &ss, &sl);
			sendto(ctx->local_fd, payload, payload_len, 0,
			       (const struct sockaddr *)&ss, sl);
		}
		s->rcv_nxt = h.seq + (uint32_t)payload_len;
		send_pkt(ctx, s, TCPF_ACK, NULL, 0);
	}
}

/*
 * Walk the tail of the *real-activity* LRU (session_touch()'s list, still
 * ordered by last_active) and nudge anything genuinely idle for >=
 * keepalive_sec with a bare ACK, to keep NAT/conntrack state alive on the
 * path to the server. Stops at the first entry that's still fresh, since
 * the list stays ordered by recency.
 *
 * Deliberately does NOT call session_touch(): a keepalive is synthetic
 * traffic, not evidence the local peer is still there, so it must never
 * feed last_active -- otherwise an abandoned session would keep getting
 * kept alive by its own keepalives forever and never reach
 * session_reap_expired()'s cutoff. last_kick only paces the resend rate
 * so the same idle session isn't re-sent every timer tick.
 */
static void send_keepalives(struct cli_ctx *ctx)
{
	time_t now = now_sec();
	time_t idle_cutoff = now - ctx->cfg->keepalive_sec;
	struct list_head *pos, *n;

	for (pos = ctx->pool.lru.prev, n = pos->prev; pos != &ctx->pool.lru;
	     pos = n, n = pos->prev) {
		struct session *s = list_entry(pos, struct session, lru);

		if (s->last_active > idle_cutoff)
			break;
		if (s->state != SESS_ESTABLISHED)
			continue;
		if (now - s->last_kick < ctx->cfg->keepalive_sec)
			continue;
		send_pkt(ctx, s, TCPF_ACK, NULL, 0);
		s->last_kick = now;
	}
}

static void shutdown_all_sessions(struct cli_ctx *ctx)
{
	struct list_head *pos, *n;

	for (pos = ctx->pool.lru.next, n = pos->next; pos != &ctx->pool.lru;
	     pos = n, n = pos->next) {
		struct session *s = list_entry(pos, struct session, lru);

		send_pkt(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
		close_session(ctx, s);
	}
}

int client_main(const struct config *cfg)
{
	struct cli_ctx ctx;
	struct epoll_event ev, events[64];
	int timer_fd;
	struct itimerspec its = {
		.it_interval = { .tv_sec = KEEPALIVE_TICK_SEC },
		.it_value = { .tv_sec = KEEPALIVE_TICK_SEC },
	};
	char abuf[64], rbuf[64];
	struct sockaddr_storage ss;
	socklen_t sl;

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;

	if (session_pool_init(&ctx.pool, (size_t)cfg->max_sessions) < 0)
		return 1;
	if (peer_index_init(&ctx.peers, (size_t)cfg->max_sessions) < 0) {
		pr_err("peer index alloc failed");
		return 1;
	}
	if (netaddr_route_lookup(&cfg->remote_addr, &ctx.local_addr) < 0) {
		pr_err("could not determine local outbound address toward %s: %s",
		       netaddr_str(&cfg->remote_addr, rbuf, sizeof(rbuf)), strerror(errno));
		return 1;
	}

	ctx.raw_fd = rawsock_open(cfg->remote_addr.family);
	if (ctx.raw_fd < 0)
		return 1;
	rawsock_filter_port(ctx.raw_fd, cfg->remote_addr.family, TCP_PORT_SRC, cfg->remote_addr.port);

	ctx.local_fd = socket(cfg->listen_addr.family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (ctx.local_fd < 0) {
		pr_err("socket(local UDP): %s", strerror(errno));
		return 1;
	}
	netaddr_to_sockaddr(&cfg->listen_addr, &ss, &sl);
	if (bind(ctx.local_fd, (const struct sockaddr *)&ss, sl) < 0) {
		pr_err("bind(local UDP %s): %s",
		       netaddr_str(&cfg->listen_addr, abuf, sizeof(abuf)), strerror(errno));
		return 1;
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

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET;
	ev.data.ptr = NULL;
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.raw_fd, &ev);

	ev.data.ptr = &ctx.local_fd;
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.local_fd, &ev);

	ev.data.ptr = &timer_fd;
	epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	pr_info("client relaying %s <-> server %s, max_sessions=%d",
		netaddr_str(&cfg->listen_addr, abuf, sizeof(abuf)),
		netaddr_str(&cfg->remote_addr, rbuf, sizeof(rbuf)), cfg->max_sessions);

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
			} else if (events[i].data.ptr == &ctx.local_fd) {
				handle_local_readable(&ctx);
			} else if (events[i].data.ptr == &timer_fd) {
				uint64_t exp;
				ssize_t r = read(timer_fd, &exp, sizeof(exp));

				(void)r;
				send_keepalives(&ctx);
				session_reap_expired(&ctx.pool, cfg->timeout_sec,
						      on_expire, &ctx);
			}
		}
	}

	pr_info("shutting down, closing %zu session(s)", ctx.pool.count);
	shutdown_all_sessions(&ctx);
	close(timer_fd);
	close(ctx.raw_fd);
	close(ctx.local_fd);
	close(ctx.epoll_fd);
	free(ctx.peers.buckets);
	session_pool_destroy(&ctx.pool);
	return 0;
}
