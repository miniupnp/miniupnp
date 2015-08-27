#include <stdlib.h>
#include "upnpdev.h"

/* freeUPNPDevlist() should be used to
 * free the chained list returned by upnpDiscover() */
void freeUPNPDevlist(struct UPNPDev * devlist)
{
	struct UPNPDev * next;
	while(devlist)
	{
		next = devlist->pNext;
		free(devlist);
		devlist = next;
	}
}

