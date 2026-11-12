/* The pinhole rules of a firewall backend, found by their key.
 *
 * The key of a pinhole is its internal address and port, its protocol, and its
 * remote address and port, which may be none: rem_host NULL, "", "*" or "::".
 * The firewall does not know the uid of a pinhole: that is the map's. A rule
 * carries its expiry and description in its label, for the expiry pass and
 * for a restart, which finds the rules of an earlier run.
 *
 * nftables and pf implement this. iptables keeps its own list of pinholes,
 * and implements it on top of that list. */
#ifndef FWPINHOLE_H_INCLUDED
#define FWPINHOLE_H_INCLUDED

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/* Add the rule of a pinhole. 0, or < 0 */
int add_pinhole_rule(const char * ifname,
                     const char * rem_host, unsigned short rem_port,
                     const char * int_client, unsigned short int_port,
                     int proto, const char * desc, unsigned int timestamp);

/* Give the rule of a pinhole a new expiry and description. 0, -2 if there is
 * no such rule, or < 0 */
int update_pinhole_rule(const char * ifname,
                        const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, const char * desc, unsigned int timestamp);

/* Delete the rule of a pinhole. 0, -2 if there is no such rule, or < 0 */
int delete_pinhole_rule(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto);

/* The packet counter of the rule of a pinhole. 0, -2 if there is no such
 * rule, or < 0 */
int get_pinhole_packets(const char * rem_host, unsigned short rem_port,
                        const char * int_client, unsigned short int_port,
                        int proto, u_int64_t * packets);

/* The pinhole rule at this place, to give a row to the rules of an earlier
 * run. rem_host is "" for none. 0, or -1 past the end */
int get_pinhole_rule_at(int index, char * rem_host, int rem_hostlen,
                        unsigned short * rem_port,
                        char * int_client, int int_clientlen,
                        unsigned short * int_port, int * proto,
                        char * desc, int desclen, unsigned int * timestamp);

/* Remove the pinhole rules past their expiry. *next_timestamp is the next
 * expiry. The number of rules removed, or < 0 */
int clean_pinhole_list(unsigned int * next_timestamp);

/* The label of a pinhole rule: "pinhole ts-<expiry>: <description>". A rule
 * of an older daemon has "pinhole-<uid> ts-<expiry>: <description>". */
static inline void
pinhole_label(char * label, size_t len, unsigned int timestamp, const char * desc)
{
	snprintf(label, len, "pinhole ts-%u: %s", timestamp, desc ? desc : "");
}

/* Read a pinhole label. 0 and *timestamp, and *desc pointing into label, or -1
 * if it is not the label of a pinhole. */
static inline int
pinhole_label_parse(const char * label, unsigned int * timestamp, const char ** desc)
{
	const char * p;
	int uid, n = 0;
	if(sscanf(label, "pinhole ts-%u: %n", timestamp, &n) == 1 && n > 0)
		p = label + n;
	else if(sscanf(label, "pinhole-%d ts-%u: %n", &uid, timestamp, &n) == 2 && n > 0)
		p = label + n;
	else if(sscanf(label, "pinhole ts-%u%n", timestamp, &n) == 1 && n > 0)
		p = label + n;	/* a label cut before its description */
	else if(sscanf(label, "pinhole-%d ts-%u%n", &uid, timestamp, &n) == 2 && n > 0)
		p = label + n;
	else
		return -1;
	if(desc != NULL)
		*desc = p;
	return 0;
}

/* 1 if rem_host stands for no remote */
static inline int
pinhole_any_remote(const char * rem_host)
{
	return rem_host == NULL || rem_host[0] == '\0' || rem_host[0] == '*' ||
	       strcmp(rem_host, "::") == 0;
}

#endif
