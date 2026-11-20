/* Addresses and keys of the memory map. memmap.c and memmap_stub.c (the map
 * of the test programs which have no table) both #include this file, so
 * there is one copy of these helpers. */
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "memmap.h"

/* The table keeps every address in 16 bytes: a.b.c.d as ::ffff:a.b.c.d. */
int
memmap_pton(const char * s, int * family, struct in6_addr * a)
{
	struct in_addr v4;

	if(s == NULL)
		return -1;
	if(inet_pton(AF_INET, s, &v4) == 1) {
		memset(a, 0, sizeof(*a));
		a->s6_addr[10] = a->s6_addr[11] = 0xff;
		memcpy(a->s6_addr + 12, &v4, sizeof(v4));
		*family = AF_INET;
		return 0;
	}
	if(inet_pton(AF_INET6, s, a) == 1) {
		*family = AF_INET6;
		return 0;
	}
	return -1;
}

/* Print an address of the table. */
const char *
memmap_ntop(int family, const struct in6_addr * a, char * buf, size_t len)
{
	if(family == AF_INET)
		return inet_ntop(AF_INET, a->s6_addr + 12, buf, len);
	return inet_ntop(AF_INET6, a, buf, len);
}

void
memmap_key_init(struct memmap_key * k, int family, int proto,
                const struct in6_addr * eaddr, unsigned short eport,
                const struct in6_addr * iaddr, unsigned short iport)
{
	memset(k, 0, sizeof(*k));
	k->family = family;
	k->proto = proto;
	k->iport = iport;
	if(iaddr != NULL)
		k->iaddr = *iaddr;
	if(family == AF_INET6) {
		/* a pinhole: no translation */
		k->eaddr = k->iaddr;
		k->eport = iport;
	} else {
		if(eaddr != NULL)
			k->eaddr = *eaddr;
		k->eport = eport;
	}
}
