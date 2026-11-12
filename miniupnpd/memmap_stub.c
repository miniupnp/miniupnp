/* The memory map for the test programs of the firewall backends, which have no table. */
#include "memmap.h"

unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return 0;
}

int
memmap_eport_redirected_elsewhere(const char * ifname, unsigned short eport, int proto,
                                  const char * iaddr, unsigned short iport)
{
	(void)ifname; (void)eport; (void)proto; (void)iaddr; (void)iport;
	return 0;
}
