/*
 * MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2015 Tomofumi Hayashi
 * (c) 2019 Paul Chambers
 * 
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution.
 */

#ifndef NFTNLRDR_H_INCLUDED
#define NFTNLRDR_H_INCLUDED

#include "../commonrdr.h"

int init_redirect(void);
void shutdown_redirect(void);

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

int
get_peer_rule_by_index(int index,
		       char * ifname, unsigned short * eport,
		       char * iaddr, int iaddrlen, unsigned short * iport,
		       int * proto,
		       char * rhost, int rhostlen, unsigned short * rport,
		       u_int64_t * packets, u_int64_t * bytes);
int
get_nat_redirect_rule(const char * nat_chain_name, const char * ifname,
		      unsigned short eport, int proto,
		      char * iaddr, int iaddrlen, unsigned short * iport,
		      char * rhost, int rhostlen,
		      u_int64_t * packets, u_int64_t * bytes);
int
get_redirect_rule_by_index(int index,
			   char * ifname, unsigned short * eport,
			   char * iaddr, int iaddrlen, unsigned short * iport,
			   int * proto,
			   char * rhost, int rhostlen,
			   u_int64_t * packets, u_int64_t * bytes);

/* in nfct_get.c */
int get_nat_ext_addr(struct sockaddr* src, struct sockaddr *dst, uint8_t proto,
		     struct sockaddr* ret_ext);

#endif
