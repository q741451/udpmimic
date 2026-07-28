/*
 * session.h - fixed-capacity session pool + open hash table + LRU.
 *
 * Shared by both server and client:
 *  - server keys sessions by the client's outer (ip, port); each session
 *    owns a dedicated remote_fd connected to the real UDP backend.
 *  - client keys sessions by its own self-chosen outer TCP port (ip is
 *    unused, always 0); a second, caller-owned index (session->pnext)
 *    is used by client.c to also look sessions up by local UDP peer
 *    address without touching this module.
 *
 * No malloc/free on the hot path: session_pool_init() allocates the
 * whole pool once; session_create()/session_remove() just move nodes
 * between a freelist, a hash bucket chain and an LRU list.
 */
#ifndef UDPMIMIC_SESSION_H
#define UDPMIMIC_SESSION_H

#include <stdint.h>
#include <time.h>
#include <netinet/in.h>

#include "list.h"

enum session_state {
	SESS_SYN_SENT,
	SESS_SYN_RCVD,
	SESS_ESTABLISHED,
	SESS_CLOSING,
};

struct session {
	struct session *hnext;		/* owned by session.c: hash chain / freelist */
	struct session *pnext;		/* free for caller use (client's 2nd index) */
	struct list_head lru;

	uint32_t key_ip;		/* network byte order; 0 on client */
	uint16_t key_port;		/* host byte order */
	uint32_t local_ip;		/* network byte order: our own addr for this session's
					 * outgoing packets (server: learned from the SYN's
					 * daddr, so multi-homed hosts reply from the same
					 * address the client used; client: its outbound
					 * interface addr, same value for every session) */

	struct sockaddr_in inner_peer;	/* client only: local UDP peer this maps to */

	uint32_t snd_nxt;
	uint32_t rcv_nxt;
	int      remote_fd;		/* server only: UDP socket connected to backend, else -1 */

	time_t   last_active;
	uint8_t  state;
};

struct session_pool {
	struct session   *entries;	/* capacity-sized array, the actual storage */
	struct session   *freelist;
	struct session  **buckets;
	size_t            nbuckets;	/* power of two */
	size_t            capacity;
	size_t            count;
	struct list_head  lru;		/* most-recently-active at head */
};

int session_pool_init(struct session_pool *pool, size_t capacity);
void session_pool_destroy(struct session_pool *pool);

struct session *session_lookup(struct session_pool *pool, uint32_t ip, uint16_t port);

/* Returns NULL if the pool is exhausted. Inserts into hash + LRU head. */
struct session *session_create(struct session_pool *pool, uint32_t ip, uint16_t port);

/* Marks activity: bumps last_active and moves to LRU head. */
void session_touch(struct session_pool *pool, struct session *s);

/* Removes from hash + LRU and returns the node to the freelist. */
void session_remove(struct session_pool *pool, struct session *s);

typedef void (*session_expire_cb)(struct session *s, void *ctx);

/*
 * Walks the LRU list from the tail (least recently active) and expires
 * everything older than `timeout` seconds, invoking cb() right before
 * each removal so the caller can release associated resources (close
 * remote_fd, epoll_ctl DEL, etc). Stops at the first still-fresh entry,
 * since the list stays ordered by recency.
 */
void session_reap_expired(struct session_pool *pool, time_t timeout,
			   session_expire_cb cb, void *ctx);

#endif /* UDPMIMIC_SESSION_H */
