/* $Id: iptcrdr.h,v 1.22 2018/07/06 12:00:10 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2018 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef IPTCRDR_H_INCLUDED
#define IPTCRDR_H_INCLUDED

#include "../commonrdr.h"

int
add_redirect_rule2(const char * ifname,
                   const char * rhost, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto);

int
add_peer_redirect_rule2(const char * ifname,
                   const char * rhost, unsigned short rport,
                   const char * eaddr, unsigned short eport,
                   const char * iaddr, unsigned short iport, int proto);

int
add_filter_rule2(const char * ifname,
                 const char * rhost, const char * iaddr,
                 unsigned short eport, unsigned short iport,
                 int proto);

int
delete_redirect_and_filter_rules(unsigned short eport, int proto);

/* only the redirect rule of eport */
int
delete_redirect_rule(const char * ifname, unsigned short eport, int proto);

int
delete_filter_rule(const char * ifname, unsigned short port, int proto);

int
add_peer_dscp_rule2(const char * ifname,
                   const char * rhost, unsigned short rport,
                   unsigned char dscp,
                   const char * iaddr, unsigned short iport, int proto);

/* Delete the PEER rules of keys[0..n-1], and their DSCP rules, in one
 * firewall transaction. Each key is one peer: the other peers of its
 * binding, and a port mapping on its external port, keep their rules. n is
 * at most OUTGOING_RULE_DELETE_MAX. 0: the transaction went through, and
 * each key has its result. -1: nothing changed. */
int
outgoing_rule_delete(struct outgoing_rule_key * keys, int n);

int get_nat_ext_addr(struct sockaddr* src, struct sockaddr *dst, uint8_t proto,
                     struct sockaddr* ret_ext);
/* fn(eport, proto, packets, bytes, arg) for each redirect rule, in one read
 * of the nat table. 0, or -1 if the table could not be read. */
int
get_redirect_rules_counters(void (*fn)(unsigned short eport, int proto,
                                       u_int64_t packets, u_int64_t bytes, void * arg),
                            void * arg);
int
get_peer_rule_by_index(int index,
                           char * ifname, unsigned short * eport,
                           char * iaddr, int iaddrlen, unsigned short * iport,
                           int * proto,
                           char * rhost, int rhostlen, unsigned short * rport,
                           u_int64_t * packets, u_int64_t * bytes);
int
get_nat_redirect_rule(const char * nat_chain_name, const char * ifname, unsigned short eport, int proto,
                  char * iaddr, int iaddrlen, unsigned short * iport,
                  char * rhost, int rhostlen,
                  u_int64_t * packets, u_int64_t * bytes);

/* for debug */
int
list_redirect_rule(const char * ifname);

#endif

