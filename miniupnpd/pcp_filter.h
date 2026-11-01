/* MiniUPnP project
 * PCP MAP FILTER policy shared with firewall backends.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PCP_FILTER_H_INCLUDED
#define PCP_FILTER_H_INCLUDED

#include <netinet/in.h>

/* At most 44 options fit in a maximum-sized MAP request (including v1).  A mapping may
 * accumulate additional peers through refreshes (RFC 6887 section 13.3). */
#define PCP_FILTER_REQUEST_MAX 44
#define PCP_FILTER_PEER_MAX 256

struct pcp_filter {
	struct in6_addr address;
	unsigned short port;
	unsigned char prefix;
};

#ifdef USE_NFTABLES
struct pcp_filter_update;

/* Stage a complete policy atomically.  -2 means EXCESSIVE_REMOTE_PEERS;
 * -1 means a firewall/resource error.  finish(0) restores the old policy. */
int nft_pcp_filter_begin(const struct in6_addr *address, unsigned short port,
                        unsigned char protocol, const char *ifname,
                        const struct pcp_filter *filters, unsigned int count,
                        struct pcp_filter_update **update);
int nft_pcp_filter_finish(struct pcp_filter_update *update, int commit);
int nft_pcp_filter_delete(const struct in6_addr *address, unsigned short port,
                         unsigned char protocol);
#endif

#endif
