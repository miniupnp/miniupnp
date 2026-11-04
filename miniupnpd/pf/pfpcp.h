/* MiniUPnP project
 * Internal interface between pf/obsdrdr.c and pf/pfpcp.c
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PFPCP_H_INCLUDED
#define PFPCP_H_INCLUDED

#include <netinet/in.h>
#include "../pcp_filter.h"

/* PCP MAP FILTER (RFC 6887 section 13.3) :
 * a filtered mapping is a group of rdr (and pass) rules, one per allowed
 * remote peer prefix/port, so traffic from other sources is never translated.
 * A policy for a mapping which is about to be created is kept pending until
 * add_redirect_rule2() and add_filter_rule2() have consumed it. */
struct pf_pcp_policy {
	struct in6_addr address;
	unsigned short port;
	unsigned char protocol;
	unsigned int count;
	struct pcp_filter filters[PCP_FILTER_PEER_MAX];
};

extern struct pf_pcp_policy * pending_policy;

/* number of filters to use for the mapping to iaddr:iport
 * (0 if no policy is pending for it) */
unsigned int
pf_pcp_pending_filters4(const char * iaddr, unsigned short iport, int proto,
                        const struct pcp_filter ** filters);

/* provided by obsdrdr.c */
extern in_addr_t last_rdr_src_addr;
extern unsigned int last_rdr_src_prefix;
extern unsigned short last_rdr_src_port;

/* when active, priv_delete_filter_rule() only removes the rule having this
 * source (used for the rules of a PCP FILTER policy) */
struct pf_filter_src_match {
	int active;
	in_addr_t addr;
	unsigned int prefix;
	unsigned short port;
};
extern struct pf_filter_src_match filter_src_match;

in_addr_t prefix_to_mask4(unsigned int prefix);
int add_redirect_rule_ex(const char * ifname,
                         in_addr_t saddr, unsigned int prefix, unsigned short sport,
                         unsigned short eport,
                         const char * iaddr, unsigned short iport, int proto,
                         const char * desc);
int add_filter_rule_ex(const char * ifname,
                       in_addr_t saddr, unsigned int prefix, unsigned short sport,
                       const char * iaddr,
                       unsigned short eport, unsigned short iport,
                       int proto, const char * desc);
/* called for each rdr rule of the anchor : index is the position in the
 * ruleset, the source restriction is saddr/prefix (prefix 0 : any address)
 * and sport (0 : any port). timestamp is the expiry of the mapping (0 : none). Return non zero to stop. It must not change
 * the rules. */
typedef int (*pf_rdr_visit_cb)(int index, const char * ifname,
                               unsigned short eport,
                               const char * iaddr, unsigned short iport,
                               int proto, const char * desc,
                               in_addr_t saddr, unsigned int prefix,
                               unsigned short sport, unsigned int timestamp,
                               void * ctx);
/* walk the rdr rules in one pass. returns 1 if stopped by visit(),
 * 0 at the end of the list, -1 on error */
int get_redirect_rules_foreach(pf_rdr_visit_cb visit, void * arg);
int priv_delete_filter_rule(const char * ifname, unsigned short iport,
                            int proto, in_addr_t iaddr);

#endif
