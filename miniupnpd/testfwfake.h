/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* A fake firewall for the unit tests: the backend functions fwsync.c calls,
 * with the prototypes of the firewall the tree is configured for. They
 * count their calls, and fail when a test sets the switches below. */
#ifndef TESTFWFAKE_H_INCLUDED
#define TESTFWFAKE_H_INCLUDED

#include <sys/types.h>
#include "config.h"
#include "fwsync.h"

extern int fail_add_redirect;	/* add_redirect_rule2() call number N fails */
extern int redirect_calls;
extern int fail_add_filter;	/* add_filter_rule2() fails */
extern int fail_delete;		/* the deletes fail */
extern int rule_present;	/* get_redirect_rule(): 1 the rule, 0 none, -1 an error */
extern const char * rule_iaddr;	/* the target of that rule */
extern unsigned short rule_iport;
extern int adds, deletes, updates;
extern unsigned short last_update_iport;
#if defined(PCP_PEER) && defined(USE_NETFILTER)
extern int peer_adds, fail_peer_add;
extern int peer_present;	/* get_peer_rule_by_index() lists the PEER rule */
#endif
#ifdef FW_MAP6
extern int map6_adds, map6_deletes, fail_map6_add_at, map6_gone;
extern int map6_lost;	/* get_map6_packets() finds no rule */
#endif

/* the firewall has the rules of ports 5000 and 5001, with counters */
#define FAKE_RULES	2

/* every switch and count back to 0, the rule there and readable */
void reset(void);

#endif
