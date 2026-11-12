/* The memory map for the test programs of the firewall backends, which have no table. */
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "memmap.h"
#include "memmap_key.c"

unsigned int
memmap_map_expiry(unsigned short eport, int proto)
{
	(void)eport; (void)proto;
	return 0;
}

void
memmap_remote_peers_partial(void)
{
}

int
memmap_eport_redirected_elsewhere(const char * ifname, const struct memmap_key * key)
{
	(void)ifname; (void)key;
	return 0;
}
