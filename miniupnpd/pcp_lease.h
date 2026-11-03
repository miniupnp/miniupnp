/* MiniUPnP project
 * The PCP lease file (<lease_file>.pcp) : the PCP and NAT-PMP mappings, their
 * FILTER peers and the PCP PEER mappings, kept across a restart.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PCP_LEASE_H_INCLUDED
#define PCP_LEASE_H_INCLUDED

#include <stdint.h>
#include "pcp_filter.h"

#ifdef PCP_LEASE_SUPPORTED

/* The protocol layer tells what it created.
 * pmp : NAT-PMP, else PCP. nonce : 3 words, NULL for NAT-PMP.
 * label : the DESCRIPTION option (RFC 7220), NULL if none.
 * A renewal with the same nonce keeps the time the mapping was created. */
void pcp_lease_note_map(int pmp, int proto, const char *iaddr,
                        unsigned short iport, const uint32_t *nonce,
                        int prefer_failure, const char *label);
/* eaddr : the translated address of the PEER mapping */
void pcp_lease_note_peer(int proto, const char *iaddr, unsigned short iport,
                         const char *raddr, unsigned short rport,
                         const char *eaddr, const uint32_t *nonce,
                         int prefer_failure, const char *label);

/* rewrite the PCP lease file from the state of the firewall */
int pcp_lease_save(void);
/* create again the mappings of the PCP lease file */
int pcp_lease_load(void);

/* is the description the one of a mapping made by PCP or NAT-PMP ? Those are
 * in the PCP lease file and not in the lease files of the UPnP code.
 * proto < 0 : only look for a PCP MAP (an IPv6 pinhole). */
int pcp_lease_owns(const char *desc, unsigned short eport, int proto);

#define PCP_LEASE_OWNS(desc, eport, proto) pcp_lease_owns(desc, eport, proto)
#else
#define PCP_LEASE_OWNS(desc, eport, proto) 0

#endif /* PCP_LEASE_SUPPORTED */

#endif
