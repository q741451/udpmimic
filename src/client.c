/*
 * client.c - relays one or more local UDP peers to a single remote
 * udpmimic server, one independent fake-TCP "connection" per local
 * peer so the server's existing multi-session logic just sees more
 * clients.
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

/* Secondary index: local UDP peer address -> session, chained via s->pnext. */
struct peer_index {
	struct session **buckets;
	size_t           nbuckets;
};

static size_t peer_hash(const struct peer_index *idx, uint32_t ip, uint16_t port)
{
	uint64_t k = ((uint64_t)ip << 16) | port;

	k *= 0x9E3779B97F4A7C15ULL;
	return (size_t)(k >> 48) & (idx->nbuckets - 1);
}

static int peer_index_init(struct peer_index *idx, size_t capacity)
{
	size_t nb = 16;

	while (nb < capacity * 2)
		nb <<= 1;
	idx->nbuckets = nb;
	idx->buckets = calloc(nb, sizeof(*idx->buckets));
	return idx->buckets ? 0 : -1;
}

static struct session *peer_index_lookup(struct peer_index *idx, uint32_t ip, uint16_t port)
{
	struct session *s = idx->buckets[peer_hash(idx, ip, port)];

	while (s) {
		if (s->inner_peer.sin_addr.s_addr == ip && s->inner_peer.sin_port == port)
			return s;
		s = s->pnext;
	}
	return NULL;
}

static void peer_index_insert(struct peer_index *idx, struct session *s)
{
	size_t b = peer_hash(idx, s->inner_peer.sin_addr.s_addr, s->inner_peer.sin_port);

	s->pnext = idx->buckets[b];
	idx->buckets[b] = s;
}

static void peer_index_remove(struct peer_index *idx, struct session *s)
{
	size_t b = peer_hash(idx, s->inner_peer.sin_addr.s_addr, s->inner_peer.sin_port);
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
	uint32_t local_ip;	/* our outbound interface addr, network byte order */
	uint16_t next_port;
	uint16_t port_tries;	/* bound on the port-allocation search below */
};

static uint32_t rand_isn(void)
{
	uint32_t v;

	if (getrandom(&v, sizeof(v), 0) != sizeof(v))
		v = (uint32_t)(now_sec() ^ (long)&v);
	return v;
}

/* getsockname() trick: connect()ing a UDP socket sends nothing, it just
 * makes the kernel resolve which local interface address routes to
 * remote_addr, which is exactly the source address our raw packets
 * need to carry. */
static int learn_local_ip(struct cli_ctx *ctx)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sa;
	socklen_t sl = sizeof(sa);
	int ret = -1;

	if (fd < 0)
		return -1;
	if (connect(fd, (const struct sockaddr *)&ctx->cfg->remote_addr,
		    sizeof(ctx->cfg->remote_addr)) == 0 &&
	    getsockname(fd, (struct sockaddr *)&sa, &sl) == 0) {
		ctx->local_ip = sa.sin_addr.s_addr;
		ret = 0;
	}
	close(fd);
	return ret;
}

static uint16_t alloc_port(struct cli_ctx *ctx)
{
	uint16_t tries;

	for (tries = 0; tries < PORT_RANGE; tries++) {
		uint16_t port = PORT_BASE + ctx->next_port;

		ctx->next_port = (ctx->next_port + 1) % PORT_RANGE;
		if (!session_lookup(&ctx->pool, 0, port))
			return port;
	}
	return 0; /* exhausted */
}

static int send_pkt(struct cli_ctx *ctx, const struct session *s, uint8_t flags,
		     const uint8_t *payload, size_t payload_len)
{
	uint8_t buf[RECV_BATCH_BUF];
	struct fake_tcp_hdr h = {
		.saddr = s->local_ip,
		.daddr = ctx->cfg->remote_addr.sin_addr.s_addr,
		.sport = s->key_port,
		.dport = ntohs(ctx->cfg->remote_addr.sin_port),
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
	return rawsock_send(ctx->raw_fd, buf, (size_t)len, h.daddr);
}

static void close_session(struct cli_ctx *ctx, struct session *s)
{
	peer_index_remove(&ctx->peers, s);
	session_remove(&ctx->pool, s);
}

static void on_expire(struct session *s, void *arg)
{
	struct cli_ctx *ctx = arg;

	pr_debug("local session port=%u expired", s->key_port);
	send_pkt(ctx, s, TCPF_RST | TCPF_ACK, NULL, 0);
	peer_index_remove(&ctx->peers, s);
}

static void handle_local_readable(struct cli_ctx *ctx)
{
	uint8_t buf[RECV_BATCH_BUF];

	for (;;) {
		struct sockaddr_in peer;
		socklen_t peer_len = sizeof(peer);
		ssize_t n = recvfrom(ctx->local_fd, buf, sizeof(buf), 0,
				      (struct sockaddr *)&peer, &peer_len);
		struct session *s;

		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				pr_warn("local recv: %s", strerror(errno));
			return;
		}

		s = peer_index_lookup(&ctx->peers, peer.sin_addr.s_addr, peer.sin_port);
		if (s) {
			session_touch(&ctx->pool, s);
			if (s->state != SESS_ESTABLISHED)
				continue; /* handshake in flight; drop like any lost UDP packet */
			send_pkt(ctx, s, TCPF_PSH | TCPF_ACK, buf, (size_t)n);
			s->snd_nxt += (uint32_t)n;
			continue;
		}

		uint16_t port = alloc_port(ctx);
		if (!port) {
			pr_warn("outer port space exhausted, dropping new local peer");
			continue;
		}
		s = session_create(&ctx->pool, 0, port);
		if (!s) {
			pr_warn("session pool exhausted (max=%d), dropping new local peer",
				ctx->cfg->max_sessions);
			continue;
		}
		s->inner_peer = peer;
		s->local_ip = ctx->local_ip;
		s->snd_nxt = rand_isn();
		s->state = SESS_SYN_SENT;
		peer_index_insert(&ctx->peers, s);

		/* Combine SYN with the first payload: SYN occupies seq, the
		 * data bytes start right after it, exactly like a normal
		 * TCP Fast Open-style opening segment. Saves a round trip
		 * and avoids buffering the first datagram. */
		send_pkt(ctx, s, TCPF_SYN | TCPF_PSH, buf, (size_t)n);
		s->snd_nxt += 1 + (uint32_t)n;

		pr_debug("new local session peer=%s:%u port=%u",
			  inet_ntoa(peer.sin_addr), ntohs(peer.sin_port), port);
	}
}

static void handle_raw_readable(struct cli_ctx *ctx)
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
		if (h.saddr != ctx->cfg->remote_addr.sin_addr.s_addr ||
		    h.sport != ntohs(ctx->cfg->remote_addr.sin_port))
			continue; /* raw socket sees all TCP on the host; filter tightly */

		s = session_lookup(&ctx->pool, 0, h.dport);
		if (!s)
			continue;

		session_touch(&ctx->pool, s);

		if (h.flags & (TCPF_RST | TCPF_FIN)) {
			pr_debug("session port=%u closed by peer", s->key_port);
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

		sendto(ctx->local_fd, payload, payload_len, 0,
		       (const struct sockaddr *)&s->inner_peer, sizeof(s->inner_peer));
		s->rcv_nxt = h.seq + (uint32_t)payload_len;
		send_pkt(ctx, s, TCPF_ACK, NULL, 0);
	}
}

/* Walk sessions from the LRU tail (oldest first) and nudge anything
 * idle for >= keepalive_sec with a bare ACK, to keep NAT/conntrack
 * state alive on the path to the server. Stops at the first entry
 * that's still fresh, since the list stays ordered by recency. */
static void send_keepalives(struct cli_ctx *ctx)
{
	time_t cutoff = now_sec() - ctx->cfg->keepalive_sec;
	struct list_head *pos, *n;

	for (pos = ctx->pool.lru.prev, n = pos->prev; pos != &ctx->pool.lru;
	     pos = n, n = pos->prev) {
		struct session *s = list_entry(pos, struct session, lru);

		if (s->last_active > cutoff)
			break;
		if (s->state == SESS_ESTABLISHED)
			send_pkt(ctx, s, TCPF_ACK, NULL, 0);
		session_touch(&ctx->pool, s);
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

	memset(&ctx, 0, sizeof(ctx));
	ctx.cfg = cfg;

	if (session_pool_init(&ctx.pool, (size_t)cfg->max_sessions) < 0)
		return 1;
	if (peer_index_init(&ctx.peers, (size_t)cfg->max_sessions) < 0) {
		pr_err("peer index alloc failed");
		return 1;
	}
	if (learn_local_ip(&ctx) < 0) {
		pr_err("could not determine local outbound address toward %s:%u: %s",
		       inet_ntoa(cfg->remote_addr.sin_addr),
		       ntohs(cfg->remote_addr.sin_port), strerror(errno));
		return 1;
	}

	ctx.raw_fd = rawsock_open();
	if (ctx.raw_fd < 0)
		return 1;

	ctx.local_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (ctx.local_fd < 0) {
		pr_err("socket(local UDP): %s", strerror(errno));
		return 1;
	}
	if (bind(ctx.local_fd, (const struct sockaddr *)&cfg->listen_addr,
		 sizeof(cfg->listen_addr)) < 0) {
		pr_err("bind(local UDP %s:%u): %s", inet_ntoa(cfg->listen_addr.sin_addr),
		       ntohs(cfg->listen_addr.sin_port), strerror(errno));
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

	pr_info("client relaying %s:%u <-> server %s:%u, max_sessions=%d",
		inet_ntoa(cfg->listen_addr.sin_addr), ntohs(cfg->listen_addr.sin_port),
		inet_ntoa(cfg->remote_addr.sin_addr), ntohs(cfg->remote_addr.sin_port),
		cfg->max_sessions);

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
