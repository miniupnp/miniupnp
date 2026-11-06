/* Keeps lease_table.c up to date from the code of the protocols. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

/* a mapping with no remote peer was added or updated (added if unknown) */
void memmap_map(unsigned short uid, unsigned short eport, const char * iaddr,
                unsigned short iport, int proto, const char * desc,
                unsigned int timestamp);
void memmap_map_gone(unsigned short eport, int proto);

/* a mapping limited to a remote peer was added or renewed */
void memmap_remote_peer(unsigned short uid, const char * raddr, unsigned short rport,
                        unsigned short eport, const char * iaddr, unsigned short iport,
                        int proto, const char * desc, unsigned int timestamp);
/* a UPnP pinhole was renewed. PCP has no uid, and renews with the key of the row */
void memmap_renew_uid(unsigned short uid, unsigned int timestamp);
void memmap_remote_peer_gone(unsigned short uid);
/* by the rule when there is no such uid : PCP has none */
void memmap_remote_peer_gone_at(unsigned short uid, const char * raddr, unsigned short rport,
                                const char * iaddr, unsigned short iport, int proto);
/* Find the rule of a pinhole in the firewall. raddr is NULL for a rule with no
 * remote host. 0 and the expiry of the rule in timestamp if it is there, -1 if
 * it is not, 1 if the firewall cannot be read. */
typedef int (*memmap_map6_lookup)(const char * raddr, unsigned short rport,
                                     const char * iaddr, unsigned short iport,
                                     int proto, unsigned int * timestamp);

/* The firewall removed the pinholes which expired. A row with an expiry at or
 * before now goes if lookup does not find its rule. A rule which is still
 * there keeps its row, with the expiry of the rule, and so does a row whose
 * rule cannot be read. */
void memmap_remote_peers_expired(unsigned int now, memmap_map6_lookup lookup);

#endif
