/* MiniUPnP project
 * The lifetime of the PCP PEER mappings, for the firewall backends.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#include "config.h"
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "peer_lease.h"

/* the name of the protocol for the logs */
static const char *
proto_name(int proto)
{
	return proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP" : "?";
}

/* seconds before trying again to remove an expired PEER rule which failed */
#define PEER_EXPIRE_RETRY	60

struct peer_lease {
	struct peer_lease * next;
	in_addr_t iaddr, raddr;
	unsigned short iport, rport;
	int proto;
	unsigned int timestamp;
};
/* a hash table on the key, as there can be thousands of PEER mappings */
#define PEER_LEASE_HASH_SIZE	4096
static struct peer_lease * peer_leases[PEER_LEASE_HASH_SIZE];

static struct peer_lease **
peer_lease_bucket(in_addr_t iaddr, unsigned short iport,
                  in_addr_t raddr, unsigned short rport, int proto)
{
	unsigned int h = 2166136261u;
	h = (h ^ (unsigned int)iaddr) * 16777619u;
	h = (h ^ (unsigned int)raddr) * 16777619u;
	h = (h ^ iport) * 16777619u;
	h = (h ^ rport) * 16777619u;
	h = (h ^ (unsigned int)proto) * 16777619u;
	return &peer_leases[h % PEER_LEASE_HASH_SIZE];
}

static struct peer_lease **
find_peer_lease(in_addr_t iaddr, unsigned short iport,
                in_addr_t raddr, unsigned short rport, int proto)
{
	struct peer_lease ** p = peer_lease_bucket(iaddr, iport, raddr, rport, proto);
	while(*p != NULL)
	{
		if((*p)->iaddr == iaddr && (*p)->iport == iport &&
		   (*p)->raddr == raddr && (*p)->rport == rport && (*p)->proto == proto)
			break;
		p = &(*p)->next;
	}
	return p;
}

int
peer_lease_exists(in_addr_t iaddr, unsigned short iport,
                  in_addr_t raddr, unsigned short rport, int proto)
{
	return *find_peer_lease(iaddr, iport, raddr, rport, proto) != NULL;
}

unsigned int
peer_lease_get(in_addr_t iaddr, unsigned short iport,
               in_addr_t raddr, unsigned short rport, int proto)
{
	struct peer_lease * l = *find_peer_lease(iaddr, iport, raddr, rport, proto);
	return l != NULL ? l->timestamp : 0;
}

int
peer_lease_set(in_addr_t iaddr, unsigned short iport,
               in_addr_t raddr, unsigned short rport, int proto,
               unsigned int timestamp)
{
	struct peer_lease ** p = find_peer_lease(iaddr, iport, raddr, rport, proto);
	if(*p == NULL)
	{
		struct peer_lease * l = calloc(1, sizeof(*l));
		if(l == NULL)
			return -1;
		l->iaddr = iaddr;
		l->iport = iport;
		l->raddr = raddr;
		l->rport = rport;
		l->proto = proto;
		l->next = NULL;
		*p = l;	/* the end of the chain of its bucket */
	}
	(*p)->timestamp = timestamp;
	return 0;
}

void
peer_lease_remove(in_addr_t iaddr, unsigned short iport,
                  in_addr_t raddr, unsigned short rport, int proto)
{
	struct peer_lease ** p = find_peer_lease(iaddr, iport, raddr, rport, proto);
	if(*p != NULL)
	{
		struct peer_lease * old = *p;
		*p = old->next;
		free(old);
	}
}

void
peer_lease_free_all(void)
{
	unsigned int b;
	for(b = 0; b < PEER_LEASE_HASH_SIZE; b++)
	{
		while(peer_leases[b] != NULL)
		{
			struct peer_lease * old = peer_leases[b];
			peer_leases[b] = old->next;
			free(old);
		}
	}
}

unsigned int
peer_lease_expire(unsigned int now, peer_lease_delete_cb delete)
{
	struct peer_lease * lease;
	unsigned int next = 0, b;
	for(b = 0; b < PEER_LEASE_HASH_SIZE; b++)
	for(lease = peer_leases[b]; lease != NULL; )
	{
		struct peer_lease * following = lease->next;
		if(lease->timestamp != 0 && lease->timestamp <= now)
		{
			char iaddr[INET_ADDRSTRLEN], raddr[INET_ADDRSTRLEN];
			/* delete() frees the lease */
			unsigned short iport = lease->iport, rport = lease->rport;
			int proto = lease->proto;
			inet_ntop(AF_INET, &lease->iaddr, iaddr, sizeof(iaddr));
			inet_ntop(AF_INET, &lease->raddr, raddr, sizeof(raddr));
			if(delete(iaddr, iport, raddr, rport, proto) < 0)
			{
				syslog(LOG_NOTICE, "Failed to expire peer map %s:%hu/%s remote %s port %hu, retrying in %d s",
				       iaddr, iport, proto_name(proto), raddr, rport,
				       PEER_EXPIRE_RETRY);
				if(next == 0 || now + PEER_EXPIRE_RETRY < next)
					next = now + PEER_EXPIRE_RETRY;
			}
			else
			{
				syslog(LOG_NOTICE, "Expire peer map %s:%hu/%s remote %s port %hu",
				       iaddr, iport, proto_name(proto), raddr, rport);
			}
		}
		else if(lease->timestamp != 0 && (next == 0 || lease->timestamp < next))
		{
			next = lease->timestamp;
		}
		lease = following;
	}
	return next;
}

/* keep the translation unit non empty */
typedef int peer_lease_unit_t;
