/* MiniUPnP project
 * PCP MAP FILTER policy shared with firewall backends.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PCP_FILTER_H_INCLUDED
#define PCP_FILTER_H_INCLUDED

#include <stdint.h>
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

/* The functions each firewall backend provides (nft_ or pf_ prefix, used
 * through the pcp_filter_* names below). Both follow this contract :
 *
 * pcp_filter_begin(address, port, protocol, ifname, filters, count, &update)
 *   Applies the FILTER options of a MAP request to the mapping of
 *   address:port/protocol : an IPv4 mapping (IPv4-mapped IPv6 address) or an
 *   IPv6 pinhole. The options are merged with the peers the mapping has
 *   (pcp_filter_merge()). ifname is the external interface, it must not be
 *   empty (nft needs it, pf ignores it). A mapping which does not exist yet
 *   gets its peers when it is created.
 *   returns  0 : done, *update has to be given to pcp_filter_finish()
 *           -1 : error (firewall, memory, invalid option)
 *           -2 : too many peers (EXCESSIVE_REMOTE_PEERS)
 *           -3 : the address family is not supported (pf without pinholes)
 *   On error the peers of the mapping are unchanged.
 * pcp_filter_finish(update, commit)
 *   commit : keep the new peers. Else the previous peers are restored.
 *   returns <0 if they could not be restored.
 * pcp_filter_delete(address, port, protocol)
 *   Forget the peers of a mapping which is deleted. returns <0 on error.
 *
 * pcp_find_map(iaddr, iport, proto, &eport, desc, desclen, &timestamp)
 *   Finds the IPv4 mapping to an internal endpoint (iport 0 : any port) in
 *   one pass over the rules. returns 0 if found, else -1.
 * pcp_find_peer(iaddr, iport, raddr, rport, proto, &eport, desc, desclen,
 *               &timestamp)
 *   Same for a PEER mapping, by the two endpoints. */

#ifdef USE_NFTABLES
struct pcp_filter_update;

int nft_pcp_filter_begin(const struct in6_addr *address, unsigned short port,
                        unsigned char protocol, const char *ifname,
                        const struct pcp_filter *filters, unsigned int count,
                        struct pcp_filter_update **update);
int nft_pcp_filter_finish(struct pcp_filter_update *update, int commit);
int nft_pcp_filter_delete(const struct in6_addr *address, unsigned short port,
                         unsigned char protocol);
int nft_pcp_find_map(const char *iaddr, unsigned short iport, int proto,
                     unsigned short *eport, char *desc, int desclen,
                     unsigned int *timestamp);
int nft_pcp_find_peer(const char *iaddr, unsigned short iport,
                      const char *raddr, unsigned short rport, int proto,
                      unsigned short *eport, char *desc, int desclen,
                      unsigned int *timestamp);
#define PCP_FIND_SUPPORTED
#define pcp_find_map nft_pcp_find_map
#define pcp_find_peer nft_pcp_find_peer
#define PCP_FILTER_SUPPORTED
#define pcp_filter_begin nft_pcp_filter_begin
#define pcp_filter_finish nft_pcp_filter_finish
#define pcp_filter_delete nft_pcp_filter_delete
#endif

#ifdef USE_PF
struct pcp_filter_update;

/* the policy is stored in the rules of the mapping */
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
int pf_pcp_find_map(const char *iaddr, unsigned short iport, int proto,
                    unsigned short *eport, char *desc, int desclen,
                    unsigned int *timestamp);
int pf_pcp_find_peer(const char *iaddr, unsigned short iport,
                     const char *raddr, unsigned short rport, int proto,
                     unsigned short *eport, char *desc, int desclen,
                     unsigned int *timestamp);
#define PCP_FIND_SUPPORTED
#define pcp_find_map pf_pcp_find_map
#define pcp_find_peer pf_pcp_find_peer
#define PCP_FILTER_SUPPORTED
#define pcp_filter_begin pf_pcp_filter_begin
#define pcp_filter_finish pf_pcp_filter_finish
#define pcp_filter_delete pf_pcp_filter_delete
#endif

#ifdef PCP_FILTER_SUPPORTED
/* the rules of the FILTER policy shared by the backends (pcp_filter.c) */
void pcp_filter_mask(struct in6_addr *a, unsigned int prefix);
int pcp_filter_equal(const struct pcp_filter *a, const struct pcp_filter *b);
/* merge the FILTER options of a request in the peers of a mapping.
 * returns 0, -1 (invalid option) or -2 (too many peers) */
int pcp_filter_merge(struct pcp_filter *peers, unsigned int *npeers,
                     const struct pcp_filter *options, unsigned int count,
                     int v4);
#endif

#endif
