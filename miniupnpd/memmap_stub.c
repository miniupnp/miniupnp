/* The memory map for the test programs of the firewall backends, which have no table. */
#include "memmap.h"

unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return 0;
}
