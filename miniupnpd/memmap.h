/* The layer between the protocols and the mapping table (lease_table.c).
 *
 * The code of the protocols works with strings and the arguments of a firewall
 * rule. The table works with rows. These functions turn the one into the other,
 * so upnpredirect.c and upnppinhole.c never touch a row. PCP and NAT-PMP call
 * those two files, so this covers all the protocols.
 *
 * A write goes to the firewall first, and here only if that worked. A row then
 * never stands for a rule which was refused.
 *
 * There are three adds, on either family. memmap_map() adds a mapping,
 * memmap_remote_peer() adds a mapping with its remote peer, and a filter has its
 * own add. iaddr gives the family. An IPv4 row is a port mapping, and an IPv6 row
 * is a pinhole: eport is iport, and the rule is that of a MAP without a remote
 * peer, or of a PEER with one. The other "peer" functions take either pinhole. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

/* The firewall added or changed a mapping with no remote peer: write its row.
 * A row on the same external port is replaced. uid is the UniqueID of a UPnP
 * pinhole, else 0. timestamp is the expiry, 0 for none. */
void memmap_map(unsigned short uid, unsigned short eport, const char * iaddr,
                unsigned short iport, int proto, const char * desc,
                unsigned int timestamp);
/* The firewall removed an IPv4 mapping: remove its row, if it has one. */
void memmap_map_gone(unsigned short eport, int proto);
/* The IPv4 mapping of an internal endpoint, with no read of the firewall. PCP
 * and NAT-PMP ask this to see if a client already has a mapping. Several
 * protocols can map one endpoint: owner (enum mapping_owner) takes the row of
 * that protocol, and -1 the first row of any. Returns 0 if found, else -1. desc
 * and timestamp may be NULL. */
int memmap_find_map(const char * iaddr, unsigned short iport, int proto,
                    int owner, unsigned short * eport, char * desc, int desclen,
                    unsigned int * timestamp);
/* The expiry of an IPv4 mapping by its external port, for a firewall backend
 * whose rule does not hold it. 0 : no expiry, or no such row. */
unsigned int memmap_map_expiry(unsigned short eport, int proto);

/* The same for a mapping limited to a remote peer, a PEER or a UPnP mapping with
 * a remote host. Its row has a struct lease_remote, and the remote is part of
 * the key of the row: rows with and without a remote can share a port. */
void memmap_remote_peer(unsigned short uid, const char * raddr, unsigned short rport,
                        unsigned short eport, const char * iaddr, unsigned short iport,
                        int proto, const char * desc, unsigned int timestamp);
/* The firewall renewed a UPnP pinhole: give its row the new expiry. PCP has no
 * uid, and renews through memmap_map() with the key of the row. */
void memmap_renew_uid(unsigned short uid, unsigned int timestamp);

/* The firewall removed the pinhole of uid: remove its row, if it has one. */
void memmap_remote_peer_gone(unsigned short uid);

/* The same, for a caller which has the rule too: if no row has the uid, find
 * the row by the rule. This is the case of a PCP pinhole, which has no uid in
 * the table. */
void memmap_remote_peer_gone_at(unsigned short uid, const char * raddr, unsigned short rport,
                                const char * iaddr, unsigned short iport, int proto);
/* The firewall ended a pass over the pinholes, and removed "removed" rules
 * (<0 : error). The rows which expired go, as their rules went. If the pass
 * removed nothing, failed or was partial, the rows stay for the next pass: a row
 * must not go while its rule may still be there. */
void memmap_remote_peers_expired(unsigned int now, int removed);
/* Tell the next memmap_remote_peers_expired() that this pass leaves expired rules in
 * the firewall, because a delete failed. */
void memmap_remote_peers_partial(void);

/* 1 if the IPv4 mapping has a row */
int memmap_map_known(unsigned short eport, int proto);
/* a port mapping by its external port. -1 if there is none */
int memmap_get_map(unsigned short eport, int proto, unsigned short * iport,
                   char * iaddr, int iaddrlen, char * desc, int desclen,
                   char * rhost, int rhostlen, unsigned int * timestamp);

#endif
