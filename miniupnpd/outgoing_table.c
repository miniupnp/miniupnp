/* The bindings and peers of the outgoing table. See outgoing_table.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>

#include "outgoing_table.h"

static struct outgoing_entry * head;
static unsigned int count;	/* the bindings */
static unsigned int peer_count;	/* the peers of all bindings */

struct outgoing_entry *
outgoing_table_new(int npeers)
{
	struct outgoing_entry * b = calloc(1, sizeof(*b));
	if(b == NULL)
		goto fail;
	if(npeers > 0) {
		b->peers = calloc((size_t)npeers, sizeof(*b->peers));
		if(b->peers == NULL) {
			free(b);
			goto fail;
		}
		b->peers_alloc = b->npeers = npeers;
	}
	b->row = 1;
	return b;
fail:
	syslog(LOG_WARNING, "outgoing table: no memory for a binding");
	return NULL;
}

void
outgoing_table_free(struct outgoing_entry * b)
{
	free(b->peers);
	free(b);
}

struct outgoing_entry *
outgoing_table_find(const struct outgoing_entry * r)
{
	struct outgoing_entry * b;
	for(b = head; b != NULL; b = b->next) {
		if(b->proto == r->proto && b->family == r->family &&
		   b->iport == r->iport && b->eport == r->eport &&
		   memcmp(&b->iaddr, &r->iaddr, sizeof(r->iaddr)) == 0 &&
		   memcmp(&b->eaddr, &r->eaddr, sizeof(r->eaddr)) == 0)
			return b;
	}
	return NULL;
}

struct outgoing_peer *
outgoing_table_find_peer(const struct outgoing_entry * b,
                         const struct in6_addr * raddr, unsigned short rport)
{
	int i;
	for(i = 0; i < b->npeers; i++) {
		struct outgoing_peer * p = &b->peers[i];
		if(p->rport == rport && memcmp(&p->raddr, raddr, sizeof(*raddr)) == 0)
			return p;
	}
	return NULL;
}

/* Add a copy of the peer p to the linked binding b. 0, or -1 if there is no
 * memory, and b then stays as it was. */
static int
add_peer(struct outgoing_entry * b, const struct outgoing_peer * p)
{
	struct outgoing_peer * a;
	if(b->npeers >= b->peers_alloc) {
		int n = b->peers_alloc > 0 ? b->peers_alloc * 2 : 1;
		a = realloc(b->peers, (size_t)n * sizeof(*a));
		if(a == NULL)
			return -1;
		b->peers = a;
		b->peers_alloc = n;
	}
	b->peers[b->npeers++] = *p;
	peer_count++;
	return 0;
}

struct outgoing_entry *
outgoing_table_link(struct outgoing_entry * b)
{
	struct outgoing_entry * o = outgoing_table_find(b);
	struct outgoing_peer * p;
	int i, r = 0;

	if(o == NULL) {
		/* the label was the caller's: the binding keeps a copy */
		if(b->label != NULL && (b->label = strdup(b->label)) == NULL)
			syslog(LOG_WARNING, "outgoing table: no memory for the label of port %hu",
			       b->eport);
		b->next = head;
		head = b;
		count++;
		peer_count += (unsigned int)b->npeers;
		return b;
	}
	/* a binding of the key is there: it takes the peers of b */
	memcpy(o->nonce, b->nonce, MAP_NONCE_LEN);
	for(i = 0; i < b->npeers; i++) {
		p = outgoing_table_find_peer(o, &b->peers[i].raddr, b->peers[i].rport);
		if(p != NULL)
			p->timestamp = b->peers[i].timestamp;
		else if(add_peer(o, &b->peers[i]) < 0)
			r = -1;
	}
	outgoing_table_free(b);
	if(r < 0) {
		syslog(LOG_WARNING, "outgoing table: no memory for a peer of port %hu",
		       o->eport);
		return NULL;
	}
	return o;
}

/* Take a linked binding off the list and free it. */
static void
unlink_binding(struct outgoing_entry * b)
{
	struct outgoing_entry ** pb;
	for(pb = &head; *pb != b; pb = &(*pb)->next)
		;
	*pb = b->next;
	count--;
	peer_count -= (unsigned int)b->npeers;
	free((char *)b->label);
	outgoing_table_free(b);
}

void
outgoing_table_remove_peer(struct outgoing_entry * b, struct outgoing_peer * p)
{
	int i = (int)(p - b->peers);
	if(b->npeers == 1) {
		unlink_binding(b);
		return;
	}
	memmove(p, p + 1, (size_t)(b->npeers - i - 1) * sizeof(*p));
	b->npeers--;
	peer_count--;
}

void
outgoing_table_remove(struct outgoing_entry * b)
{
	unlink_binding(b);
}

unsigned int
outgoing_table_expire(unsigned int now)
{
	struct outgoing_entry * b, * next;
	unsigned int n = 0;
	int i;

	for(b = head; b != NULL; b = next) {
		next = b->next;
		for(i = b->npeers - 1; i >= 0; i--) {
			if(b->peers[i].timestamp == 0 || b->peers[i].timestamp > now)
				continue;
			n++;
			if(b->npeers == 1) {
				unlink_binding(b);
				break;
			}
			outgoing_table_remove_peer(b, &b->peers[i]);
		}
	}
	return n;
}

unsigned int
outgoing_table_count(void)
{
	return count;
}

unsigned int
outgoing_table_peer_count(void)
{
	return peer_count;
}

void
outgoing_table_clear(void)
{
	while(head != NULL)
		unlink_binding(head);
}

/* the name of a protocol, for the dump. Not proto_itoa(): the table links
 * alone in testoutgoingtable */
static const char *
proto_name(int proto)
{
	switch(proto) {
	case IPPROTO_TCP:	return "TCP";
	case IPPROTO_UDP:	return "UDP";
#ifdef IPPROTO_UDPLITE
	case IPPROTO_UDPLITE:	return "UDPLITE";
#endif
	default:		return "?";
	}
}

void
outgoing_table_dump(FILE * f)
{
	const struct outgoing_entry * b;
	char iaddr[INET6_ADDRSTRLEN], eaddr[INET6_ADDRSTRLEN], raddr[INET6_ADDRSTRLEN];
	int i;

	fprintf(f, "# outgoing table: %u bindings, %u peers\n", count, peer_count);
	for(b = head; b != NULL; b = b->next) {
		if(map_ntop(b->family, &b->iaddr, iaddr, sizeof(iaddr)) == NULL)
			iaddr[0] = '\0';
		if(map_ntop(b->family, &b->eaddr, eaddr, sizeof(eaddr)) == NULL)
			eaddr[0] = '\0';
		fprintf(f, "PEER %s %s [%s]:%hu -> [%s]:%hu nonce=",
		        b->family == AF_INET ? "IPv4" : "IPv6", proto_name(b->proto),
		        iaddr, b->iport, eaddr, b->eport);
		for(i = 0; i < MAP_NONCE_LEN; i++)
			fprintf(f, "%02x", b->nonce[i]);
		if(b->label != NULL)
			fprintf(f, " label=\"%s\"", b->label);
		fputc('\n', f);
		for(i = 0; i < b->npeers; i++) {
			const struct outgoing_peer * p = &b->peers[i];
			if(map_ntop(b->family, &p->raddr, raddr, sizeof(raddr)) == NULL)
				raddr[0] = '\0';
			fprintf(f, "\tpeer [%s]:%hu expiry=%u\n", raddr, p->rport, p->timestamp);
		}
	}
}
