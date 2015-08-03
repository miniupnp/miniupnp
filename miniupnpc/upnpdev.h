#ifndef UPNPDEV_H_INCLUDED
#define UPNPDEV_H_INCLUDED

#include "miniupnpc_declspec.h"

#ifdef __cplusplus
extern "C" {
#endif

struct UPNPDev {
	struct UPNPDev * pNext;
	char * descURL;
	char * st;
	unsigned int scope_id;
	char * usn;
	char buffer[3];
};

/* freeUPNPDevlist()
 * free list returned by upnpDiscover() */
MINIUPNP_LIBSPEC void freeUPNPDevlist(struct UPNPDev * devlist);


#ifdef __cplusplus
}
#endif


#endif
