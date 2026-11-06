/* See memmap.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"
#include "upnpredirect.h"
#include "lease_table.h"
#include "memmap.h"

static int
v4_mapped(const char * s, struct in6_addr * a)
{
	struct in_addr v4;
	if(inet_pton(AF_INET, s, &v4) != 1)
		return -1;
	memset(a, 0, sizeof(*a));
	a->s6_addr[10] = a->s6_addr[11] = 0xff;
	memcpy(a->s6_addr + 12, &v4, sizeof(v4));
	return 0;
}

static int
hex_value(int c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	return c - 'A' + 10;
}

/* kind and nonce of a mapping, from its description */
static void
set_owner(struct lease_entry * e, const char * desc, unsigned short eport, int proto)
{
	int i;
	memset(e->nonce, 0, sizeof(e->nonce));
	switch(mapping_owner_of(desc, eport, proto)) {
	case MAPPING_PCP:
		e->kind = LEASE_PCP_MAP;
		desc += strlen(desc) - 24;
		for(i = 0; i < LEASE_NONCE_LEN; i++)
			e->nonce[i] = (unsigned char)(hex_value(desc[2 * i]) * 16 +
			                              hex_value(desc[2 * i + 1]));
		break;
	case MAPPING_NATPMP:
		e->kind = LEASE_NATPMP;
		break;
	default:
		e->kind = LEASE_UPNP;
	}
}

void
memmap_map(const char * rhost, unsigned short eport, const char * iaddr,
           unsigned short iport, int proto, const char * desc,
           unsigned int timestamp)
{
	struct lease_entry e, * row;
	struct in6_addr raddr;
	int has_remote = rhost != NULL && rhost[0] != '\0' && strcmp(rhost, "*") != 0 &&
	                 v4_mapped(rhost, &raddr) == 0;

	memset(&e, 0, sizeof(e));
	if(v4_mapped(iaddr, &e.iaddr) < 0)
		return;
	row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL)
		lease_table_remove(row);
	e.family = AF_INET;
	e.proto = (unsigned char)proto;
	e.eport = eport;
	e.iport = iport;
	e.expiry = timestamp;
	e.label = (char *)desc;	/* copied */
	set_owner(&e, desc ? desc : "", eport, proto);
	row = lease_table_add(&e, has_remote ? &raddr : NULL, 0);
	if(row == NULL)
		syslog(LOG_WARNING, "lease table: could not add %hu %d", eport, proto);
}

void
memmap_map_gone(unsigned short eport, int proto)
{
	struct lease_entry * row = lease_table_find_mapping(proto, AF_INET, NULL, eport);
	if(row != NULL)
		lease_table_remove(row);
}
