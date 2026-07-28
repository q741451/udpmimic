/* rawsock.c - build/parse/send/receive fake-TCP packets on a raw socket. */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "common.h"
#include "checksum.h"
#include "rawsock.h"

int rawsock_open(void)
{
	int fd, one = 1;

	fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
	if (fd < 0) {
		pr_err("socket(SOCK_RAW, IPPROTO_TCP): %s (need root/CAP_NET_RAW)",
		       strerror(errno));
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		pr_err("setsockopt(IP_HDRINCL): %s", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

int rawsock_build(uint8_t *buf, size_t bufcap, const struct fake_tcp_hdr *h,
		   const uint8_t *payload, size_t payload_len)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	size_t total = sizeof(*ip) + sizeof(*tcp) + payload_len;
	static uint16_t ip_id;

	if (total > bufcap)
		return -1;

	memset(buf, 0, sizeof(*ip) + sizeof(*tcp));

	ip = (struct iphdr *)buf;
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons((uint16_t)total);
	ip->id = htons(ip_id++);
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = h->saddr;
	ip->daddr = h->daddr;
	ip->check = 0;
	ip->check = inet_checksum(ip, sizeof(*ip), 0);

	tcp = (struct tcphdr *)(buf + sizeof(*ip));
	tcp->source = htons(h->sport);
	tcp->dest = htons(h->dport);
	tcp->seq = htonl(h->seq);
	tcp->ack_seq = htonl(h->ack);
	tcp->doff = 5;
	tcp->syn = !!(h->flags & TCPF_SYN);
	tcp->ack = !!(h->flags & TCPF_ACK);
	tcp->psh = !!(h->flags & TCPF_PSH);
	tcp->fin = !!(h->flags & TCPF_FIN);
	tcp->rst = !!(h->flags & TCPF_RST);
	tcp->window = htons(h->window);
	tcp->urg_ptr = 0;
	tcp->check = 0;

	if (payload_len)
		memcpy(buf + sizeof(*ip) + sizeof(*tcp), payload, payload_len);

	tcp->check = tcp_checksum(ip, tcp, payload, payload_len);

	return (int)total;
}

int rawsock_send(int fd, const uint8_t *pkt, size_t pkt_len, uint32_t daddr)
{
	struct sockaddr_in dst;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = daddr;

	n = sendto(fd, pkt, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		pr_warn("raw sendto: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int rawsock_parse(const uint8_t *buf, size_t len, struct fake_tcp_hdr *h,
		   const uint8_t **payload, size_t *payload_len)
{
	const struct iphdr *ip;
	const struct tcphdr *tcp;
	size_t ip_hlen, tcp_hlen, total;

	if (len < sizeof(*ip))
		return -1;

	ip = (const struct iphdr *)buf;
	if (ip->version != 4)
		return -1;

	ip_hlen = (size_t)ip->ihl * 4;
	if (ip_hlen < sizeof(*ip) || len < ip_hlen + sizeof(*tcp))
		return -1;

	if (ip->protocol != IPPROTO_TCP)
		return -1;

	tcp = (const struct tcphdr *)(buf + ip_hlen);
	tcp_hlen = (size_t)tcp->doff * 4;
	if (tcp_hlen < sizeof(*tcp) || ip_hlen + tcp_hlen > len)
		return -1;

	total = ntohs(ip->tot_len);
	if (total < ip_hlen + tcp_hlen || total > len)
		total = len; /* tolerate padded frames; clamp to what we got */

	h->saddr = ip->saddr;
	h->daddr = ip->daddr;
	h->sport = ntohs(tcp->source);
	h->dport = ntohs(tcp->dest);
	h->seq = ntohl(tcp->seq);
	h->ack = ntohl(tcp->ack_seq);
	h->window = ntohs(tcp->window);
	h->flags = 0;
	if (tcp->syn) h->flags |= TCPF_SYN;
	if (tcp->ack) h->flags |= TCPF_ACK;
	if (tcp->psh) h->flags |= TCPF_PSH;
	if (tcp->fin) h->flags |= TCPF_FIN;
	if (tcp->rst) h->flags |= TCPF_RST;

	*payload = buf + ip_hlen + tcp_hlen;
	*payload_len = total - (ip_hlen + tcp_hlen);

	return 0;
}
