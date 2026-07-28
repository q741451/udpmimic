/* session.c - pool + hash table + LRU, see session.h for the design. */
#include "common.h"
#include "session.h"

static size_t next_pow2(size_t n)
{
	size_t p = 16;

	while (p < n)
		p <<= 1;
	return p;
}

int session_pool_init(struct session_pool *pool, size_t capacity)
{
	size_t i;

	memset(pool, 0, sizeof(*pool));

	pool->capacity = capacity;
	pool->nbuckets = next_pow2(capacity * 2);

	pool->entries = calloc(capacity, sizeof(*pool->entries));
	pool->buckets = calloc(pool->nbuckets, sizeof(*pool->buckets));
	if (!pool->entries || !pool->buckets) {
		pr_err("session pool alloc failed for capacity=%zu", capacity);
		free(pool->entries);
		free(pool->buckets);
		return -1;
	}

	INIT_LIST_HEAD(&pool->lru);

	pool->freelist = NULL;
	for (i = 0; i < capacity; i++) {
		struct session *s = &pool->entries[i];

		s->remote_fd = -1;
		s->hnext = pool->freelist;
		pool->freelist = s;
	}

	return 0;
}

void session_pool_destroy(struct session_pool *pool)
{
	free(pool->entries);
	free(pool->buckets);
	memset(pool, 0, sizeof(*pool));
}

struct session *session_lookup(struct session_pool *pool, const struct netaddr *key)
{
	struct session *s = pool->buckets[netaddr_hash(pool->nbuckets, key)];

	while (s) {
		if (netaddr_equal(&s->key, key))
			return s;
		s = s->hnext;
	}
	return NULL;
}

struct session *session_create(struct session_pool *pool, const struct netaddr *key)
{
	struct session *s;
	size_t b;

	if (!pool->freelist)
		return NULL;

	s = pool->freelist;
	pool->freelist = s->hnext;

	memset(s, 0, sizeof(*s));
	s->remote_fd = -1;
	s->key = *key;
	s->last_active = now_sec();

	b = netaddr_hash(pool->nbuckets, key);
	s->hnext = pool->buckets[b];
	pool->buckets[b] = s;

	list_add(&s->lru, &pool->lru);
	pool->count++;

	return s;
}

void session_touch(struct session_pool *pool, struct session *s)
{
	s->last_active = now_sec();
	list_move(&s->lru, &pool->lru);
}

void session_remove(struct session_pool *pool, struct session *s)
{
	struct session **pp = &pool->buckets[netaddr_hash(pool->nbuckets, &s->key)];

	while (*pp) {
		if (*pp == s) {
			*pp = s->hnext;
			break;
		}
		pp = &(*pp)->hnext;
	}

	list_del(&s->lru);
	pool->count--;

	s->hnext = pool->freelist;
	pool->freelist = s;
}

void session_reap_expired(struct session_pool *pool, time_t timeout,
			   session_expire_cb cb, void *ctx)
{
	time_t cutoff = now_sec() - timeout;
	struct list_head *pos, *n;

	/* LRU list is ordered most-active-first; walk from the tail. */
	for (pos = pool->lru.prev, n = pos->prev; pos != &pool->lru; pos = n, n = pos->prev) {
		struct session *s = list_entry(pos, struct session, lru);

		if (s->last_active > cutoff)
			break; /* everything before this is even fresher */

		if (cb)
			cb(s, ctx);
		session_remove(pool, s);
	}
}
