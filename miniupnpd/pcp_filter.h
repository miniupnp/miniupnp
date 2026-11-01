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
#define PCP_FILTER_SUPPORTED
#define pcp_filter_begin nft_pcp_filter_begin
#define pcp_filter_finish nft_pcp_filter_finish
#define pcp_filter_delete nft_pcp_filter_delete
#endif

#ifdef USE_PF
struct pcp_filter_update;

/* Same contract as the nftables functions, but the policy is stored in the
 * rules of the mapping.  -3 means the address family is not supported. */
int pf_pcp_filter_begin(const struct in6_addr *address, unsigned short port,
                        unsigned char protocol, const char *ifname,
                        const struct pcp_filter *filters, unsigned int count,
                        struct pcp_filter_update **update);
int pf_pcp_filter_finish(struct pcp_filter_update *update, int commit);
int pf_pcp_filter_delete(const struct in6_addr *address, unsigned short port,
                         unsigned char protocol);
/* used by pf/pfpinhole.c */
unsigned int pf_pcp_pending_filters6(const struct in6_addr *address,
                                     unsigned short port, int protocol,
                                     const struct pcp_filter **filters);
unsigned int pf_pinhole_group_get(const struct in6_addr *dst, unsigned short port,
                                  int proto, struct pcp_filter *filters,
                                  unsigned int max, unsigned int *nfilters,
                                  char *desc, int desclen,
                                  unsigned int *timestamp, char *ifname);
int pf_pinhole_group_add(const char *ifname, const struct in6_addr *dst,
                         unsigned short port, int proto, const char *desc,
                         unsigned int timestamp, const struct pcp_filter *f);
int pf_pinhole_group_remove(const struct in6_addr *dst, unsigned short port,
                            int proto, const struct pcp_filter *f);
#define PCP_FILTER_SUPPORTED
#define pcp_filter_begin pf_pcp_filter_begin
#define pcp_filter_finish pf_pcp_filter_finish
#define pcp_filter_delete pf_pcp_filter_delete
#endif

#endif
