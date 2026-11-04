/* $Id: nftnlrdr_misc.c,v 1.22 2025/04/21 22:02:43 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2015 Tomofumi Hayashi
 * (c) 2019 Paul Chambers
 * (c) 2019-2026 Thomas Bernard
 *
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <stddef.h>
#include <syslog.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/ipv6.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>

#include "../commonrdr.h"
#include "nftnlrdr.h"
#include "nftnlrdr_misc.h"
#include "../peer_lease.h"
#include "../macros.h"
#include "../pcp_filter.h"


#ifdef DEBUG
#define d_printf(x) do { printf x; } while (0)
#else
#define d_printf(x)
#endif

#if defined(DEBUG) && defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && (__GNUC__ >= 3)
/* disambiguate log messages by adding position in source. GNU C99 or later. Pesky trailing comma... */
#define log_error( msg, ...)	syslog(LOG_ERR, "%s[%d]: " msg, __func__, __LINE__, ##__VA_ARGS__ )
#define log_debug( msg, ...)	syslog(LOG_DEBUG, "%s[%d]: " msg, __func__, __LINE__, ##__VA_ARGS__ )
#else
/* original style */
#define log_error(args...)	syslog(LOG_ERR, args)
#define log_debug(args...)	syslog(LOG_DEBUG, args)
#endif

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

/* maximum length of USERDATA, used for description */
#define NFTNL_RULE_USERDATA_MAX_LEN 256

#define RULE_CACHE_INVALID  0
#define RULE_CACHE_VALID    1

const char * nft_table = "filter";
const char * nft_nat_table = "filter";
const char * nft_prerouting_chain = "prerouting_miniupnpd";
const char * nft_postrouting_chain = "postrouting_miniupnpd";
const char * nft_forward_chain = "miniupnpd";
int nft_nat_family = NFPROTO_INET;
int nft_ipv4_family = NFPROTO_INET;
int nft_ipv6_family = NFPROTO_INET;

static struct mnl_socket *mnl_sock = NULL;
static uint32_t mnl_portid = 0;
static uint32_t mnl_seq = 0;
/* Rule builders must not install a partially constructed PCP policy. */
static int expr_alloc_failed;

// FILTER
struct rule_list head_filter = LIST_HEAD_INITIALIZER(head_filter);
// DNAT
struct rule_list head_redirect = LIST_HEAD_INITIALIZER(head_redirect);
// SNAT
struct rule_list head_peer = LIST_HEAD_INITIALIZER(head_peer);

static uint32_t rule_list_filter_validate = RULE_CACHE_INVALID;
static uint32_t rule_list_redirect_validate = RULE_CACHE_INVALID;
static uint32_t rule_list_peer_validate = RULE_CACHE_INVALID;
/* the entry of the last rule deleted from each list, see rule_cache_remove() */
static rule_t *rule_deleted_filter;
static rule_t *rule_deleted_redirect;
static rule_t *rule_deleted_peer;

static rule_t **
deleted_slot(const struct rule_list *head)
{
	return head == &head_filter ? &rule_deleted_filter :
	       head == &head_peer ? &rule_deleted_peer : &rule_deleted_redirect;
}


/*
 * return : 0 for OK, -1 for error
 */
int
nft_mnl_connect(void)
{
	mnl_sock = mnl_socket_open(NETLINK_NETFILTER);
	if (mnl_sock == NULL) {
		log_error("mnl_socket_open() FAILED: %m");
		return -1;
	}
	if (mnl_socket_bind(mnl_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		log_error("mnl_socket_bind() FAILED: %m");
		return -1;
	}
	mnl_portid = mnl_socket_get_portid(mnl_sock);
	syslog(LOG_INFO, "mnl_socket bound, port_id=%u", mnl_portid);
	return 0;
}

void
nft_mnl_disconnect(void)
{
	if (mnl_sock != NULL) {
		mnl_socket_close(mnl_sock);
		mnl_sock = NULL;
	}
}

#ifdef DEBUG
void
print_rule(const char *func, int line, const struct nftnl_rule *rule)
{
	fprintf(stdout, "%s[%d]: ", func, line);
	nftnl_rule_fprintf(stdout, rule, NFTNL_OUTPUT_DEFAULT, 0);
}

void
print_rule_t(const char *func, int line, const rule_t *r)
{
	fprintf(stdout, "%s[%d]: ", func, line);
	printf("%s %s %d %hu => %hu => %hu\n", r->table, r->chain, (int)r->type,
	       r->sport, r->dport, r->nat_port);
}

/* print out the "filter" and "nat" tables */
void
print_redirect_rules(const char * ifname)
{
	rule_t *p;
	int i;
	UNUSED(ifname);

	refresh_nft_cache_filter();
	i = 1;
	LIST_FOREACH(p, &head_filter, entry) {
		print_rule_t("filter", i++, p);
	}

	refresh_nft_cache_redirect();
	i = 1;
	LIST_FOREACH(p, &head_redirect, entry) {
		print_rule_t("redirect", i++, p);
	}

	refresh_nft_cache_peer();
	i = 1;
	LIST_FOREACH(p, &head_peer, entry) {
		print_rule_t("peer", 0, p);
	}
}
#endif

static enum rule_reg_type *
get_reg_type_ptr(rule_t *r, uint32_t dreg)
{
	switch (dreg) {
	case NFT_REG_1:
		return &r->reg1_type;
	case NFT_REG_2:
		return &r->reg2_type;
	default:
		return NULL;
	}
}

static uint32_t *
get_reg_val_ptr(rule_t *r, uint32_t dreg)
{
	switch (dreg) {
	case NFT_REG_1:
		return &r->reg1_val;
	case NFT_REG_2:
		return &r->reg2_val;
	default:
		return NULL;
	}
}

static void
set_reg (rule_t *r, uint32_t dreg, enum rule_reg_type type, uint32_t val)
{
	if (dreg == NFT_REG_1) {
		r->reg1_type = type;
		if (type == RULE_REG_IMM_VAL) {
			r->reg1_val = val;
		}
	} else if (dreg == NFT_REG_2) {
		r->reg2_type = type;
		if (type == RULE_REG_IMM_VAL) {
			r->reg2_val = val;
		}
	} else if (dreg == NFT_REG_VERDICT) {
		if (r->type == RULE_FILTER) {
			r->filter_action = val;
		}
	} else {
		log_error("unknown reg:%d", dreg);
	}
	return ;
}

static void
parse_rule_immediate(struct nftnl_expr *e, rule_t *r)
{
	uint32_t dreg, reg_val, reg_len;

	dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_DREG);

	if (dreg == NFT_REG_VERDICT) {
		reg_val = nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_VERDICT);
	} else {
		const void * p = nftnl_expr_get(e, NFTNL_EXPR_IMM_DATA, &reg_len);
		if (p == NULL) {
			log_error("nftnl_expr_get() failed for reg:%u", dreg);
			return;
		} else switch(reg_len) {
			case sizeof(uint32_t):
				reg_val = *(const uint32_t *)p;
				break;
			case sizeof(uint16_t):
				reg_val = *(const uint16_t *)p;
				break;
			default:
				log_error("nftnl_expr_get() reg_len=%u", reg_len);
				return;
		}
	}

	set_reg(r, dreg, RULE_REG_IMM_VAL, reg_val);
}

static void
parse_rule_counter(struct nftnl_expr *e, rule_t *r)
{
	r->type = RULE_COUNTER;
	r->bytes = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_BYTES);
	r->packets = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_PACKETS);
}

static void
parse_rule_meta(struct nftnl_expr *e, rule_t *r)
{
	uint32_t key = nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY);
	uint32_t dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_META_DREG);

	/* ToDo: body of both cases are identical - bug? */
	switch (key) {
	case NFT_META_IIF:
		set_reg(r, dreg, RULE_REG_IIF, 0);
		break;
	case NFT_META_OIF:
		set_reg(r, dreg, RULE_REG_IIF, 0);
		break;
	case NFT_META_NFPROTO:
		set_reg(r, dreg, RULE_REG_PROTO, 0);
		break;
	default:
		log_debug("parse_rule_meta: key %d unsupported\n", key);
		break;
	}
}

static void
parse_rule_nat(struct nftnl_expr *e, rule_t *r)
{
	uint32_t addr_min_reg, addr_max_reg, proto_min_reg, proto_max_reg;
	uint16_t proto_min_val = 0;
	uint32_t * reg_val_ptr;
	r->type = RULE_NAT;

	r->nat_type = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_TYPE);
	r->family = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_FAMILY);
	addr_min_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN);
	addr_max_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MAX);
	/* see expr_add_nat() :
	 * NFTNL_EXPR_NAT_REG_PROTO_MIN/NFTNL_EXPR_NAT_REG_PROTO_MAX is used
	 * for destination port */
	proto_min_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MIN);
	proto_max_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MAX);

	if (addr_min_reg != addr_max_reg ||
	    proto_min_reg != proto_max_reg) {
		log_error( "Unsupport proto/addr range for NAT");
	}

	reg_val_ptr = get_reg_val_ptr(r, proto_min_reg);
	if (reg_val_ptr != NULL) {
		proto_min_val = htons((uint16_t)*reg_val_ptr);
		syslog(LOG_DEBUG, "%s: proto_min_reg %u : %08x => %hd", "parse_rule_nat", proto_min_reg, *reg_val_ptr, proto_min_val);
	} else {
		syslog(LOG_ERR, "%s: invalid proto_min_reg %u", "parse_rule_nat", proto_min_reg);
	}
	reg_val_ptr = get_reg_val_ptr(r, addr_min_reg);
	if (reg_val_ptr != NULL) {
		/* destination address */
		r->nat_addr = (in_addr_t)*reg_val_ptr;
		/* destination port */
		r->nat_port = proto_min_val;
	} else {
		syslog(LOG_ERR, "%s: invalid addr_min_reg %u", "parse_rule_nat", addr_min_reg);
	}

	set_reg(r, NFT_REG_1, RULE_REG_NONE, 0);
	set_reg(r, NFT_REG_2, RULE_REG_NONE, 0);
}

static void
parse_rule_payload(struct nftnl_expr *e, rule_t *r)
{
	uint32_t  base, dreg, offset, len;
	uint32_t  *regptr;

	dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_DREG);
	base = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_BASE);
	offset = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET);
	len = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_LEN);
	regptr = get_reg_type_ptr(r, dreg);
	if (regptr == NULL) {
		syslog(LOG_ERR, "%s: unsupported dreg %u", "parse_rule_payload", dreg);
		return;
	}

	switch (base) {
	case NFT_PAYLOAD_NETWORK_HEADER:
		if (offset == offsetof(struct iphdr, daddr) &&
		    len == sizeof(in_addr_t)) {
			*regptr = RULE_REG_IP_DEST_ADDR;
		} else if (offset == offsetof(struct iphdr, saddr) &&
			   len == sizeof(in_addr_t)) {
			*regptr = RULE_REG_IP_SRC_ADDR;
		} else if (offset == offsetof(struct iphdr, saddr) &&
			   len == sizeof(in_addr_t) * 2) {
			*regptr = RULE_REG_IP_SD_ADDR;
		} else if (offset == offsetof(struct iphdr, protocol) &&
			   len == sizeof(uint8_t)) {
			*regptr = RULE_REG_IP_PROTO;
		} else if (offset == offsetof(struct ipv6hdr, nexthdr) &&
			   len == sizeof(uint8_t)) {
			*regptr = RULE_REG_IP6_PROTO;
		} else if (offset == offsetof(struct ipv6hdr, daddr) &&
		    len == sizeof(struct in6_addr)) {
			*regptr = RULE_REG_IP6_DEST_ADDR;
		} else if (offset == offsetof(struct ipv6hdr, saddr) &&
			   len == sizeof(struct in6_addr)) {
			*regptr = RULE_REG_IP6_SRC_ADDR;
		} else if (offset == offsetof(struct ipv6hdr, saddr) &&
			   len == sizeof(struct in6_addr) * 2) {
			*regptr = RULE_REG_IP6_SD_ADDR;
		} else {
			syslog(LOG_WARNING,
				   "%s: Unsupported payload: (dreg:%u, base:NETWORK_HEADER, offset:%u, len:%u)",
				   "parse_rule_payload", dreg, offset, len);
		}
		break;
	case NFT_PAYLOAD_TRANSPORT_HEADER:
		/* in both UDP and TCP headers, source port is at offset 0,
		 * destination port at offset 2 */
		if (offset == offsetof(struct tcphdr, dest) &&
		    len == sizeof(uint16_t)) {
			*regptr = RULE_REG_TCP_DPORT;
		} else if (offset == offsetof(struct tcphdr, source) &&
			   len == sizeof(uint16_t)) {
			*regptr = RULE_REG_TCP_SPORT;
		} else if (offset == offsetof(struct tcphdr, source) &&
			   len == sizeof(uint16_t) * 2) {
			*regptr = RULE_REG_TCP_SD_PORT;
		} else {
			syslog(LOG_WARNING,
				   "%s: Unsupported payload: (dreg:%u, base:TRANSPORT_HEADER, offset:%u, len:%u)",
				   "parse_rule_payload", dreg, offset, len);
		}
		break;
	default:
		syslog(LOG_WARNING,
			   "%s: Unsupported payload: (dreg:%u, base:%u, offset:%u, len:%u)",
			   "parse_rule_payload", dreg, base, offset, len);
		break;
	}

}

/*
 *
 * Note: Currently support only NFT_REG_1
 */
static void
parse_rule_cmp(struct nftnl_expr *e, rule_t *r)
{
	uint32_t data_len = 0;
	const void *data_val;
	uint32_t op, sreg;

	op = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_OP);

	if (op != NFT_CMP_EQ) {
		/* not a cmp expression, so bail out early */
		return;
	}

	sreg = nftnl_expr_get_u32(e, NFTNL_EXPR_CMP_SREG);

	if (sreg != NFT_REG_1) {
		log_error( "parse_rule_cmp: Unsupport reg:%d", sreg);
		return;
	}

	data_val = nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &data_len);
	if (data_val == NULL) {
		log_error( "parse_rule_cmp: nftnl_expr_get(NFTNL_EXPR_CMP_DATA) returned NULL");
		return;
	}

	switch (r->reg1_type) {
	case RULE_REG_IIF:
		if (data_len == sizeof(uint32_t)) {
			r->ingress_ifidx = *(const uint32_t *)data_val;
		}
		break;
	case RULE_REG_IP_SRC_ADDR:
		if (data_len == sizeof(in_addr_t)) {
			r->saddr = *(const in_addr_t *)data_val;
		}
		break;
	case RULE_REG_IP6_SRC_ADDR:
		if (data_len == sizeof(struct in6_addr)) {
			r->saddr6 = *(const struct in6_addr *)data_val;
		}
		break;
	case RULE_REG_IP_DEST_ADDR:
		if (data_len == sizeof(in_addr_t)) {
			r->daddr = *(const in_addr_t *)data_val;
		}
		break;
	case RULE_REG_IP6_DEST_ADDR:
		if (data_len == sizeof(struct in6_addr)) {
			r->daddr6 = *(const struct in6_addr *)data_val;
		}
		break;
	case RULE_REG_IP_SD_ADDR:
		if (data_len == sizeof(in_addr_t) * 2) {
			const in_addr_t *addrp = (const in_addr_t *)data_val;
			r->saddr = addrp[0];
			r->daddr = addrp[1];
		}
		break;
	case RULE_REG_IP6_SD_ADDR:
		if (data_len == sizeof(struct in6_addr) * 2) {
			const struct in6_addr *addrp6 = (const struct in6_addr *)data_val;
			r->saddr6 = addrp6[0];
			r->daddr6 = addrp6[1];
		}
		break;
	case RULE_REG_IP_PROTO:
	case RULE_REG_IP6_PROTO:
		if (data_len == sizeof(uint8_t)) {
			r->proto = *(const uint8_t *)data_val;
		}
		break;
	case RULE_REG_TCP_SPORT:
		if (data_len == sizeof(uint16_t)) {
			r->sport = ntohs(*(const uint16_t *)data_val);
		}
		break;
	case RULE_REG_TCP_DPORT:
		if (data_len == sizeof(uint16_t)) {
			r->dport = ntohs(*(const uint16_t *)data_val);
		}
		break;
	case RULE_REG_TCP_SD_PORT:
		if (data_len == sizeof(uint16_t) * 2) {
			const uint16_t * ports = (const uint16_t *)data_val;
			r->sport = ntohs(ports[0]);
			r->dport = ntohs(ports[1]);
		}
		break;
	case RULE_REG_PROTO:
		/* value is 8bits either NFPROTO_IPV4=2 or NFPROTO_IPV6=10 */
		/* we don't do anything with it for now */
		break;
	default:
		log_debug("Unknown cmp (r1type:%d, data_len:%d, op:%d)",
			   r->reg1_type, data_len, op);
		/* return early - don't modify r->reg1_type */
		return;
	}

	r->reg1_type = RULE_REG_NONE;
	return;
}

static int
rule_expr_cb(struct nftnl_expr *e, rule_t *r)
{
	const char *attr_name = nftnl_expr_get_str(e, NFTNL_EXPR_NAME);

	if (strncmp("cmp", attr_name, sizeof("cmp")) == 0) {
		parse_rule_cmp(e, r);
	} else if (strncmp("nat", attr_name, sizeof("nat")) == 0) {
		parse_rule_nat(e, r);
	} else if (strncmp("meta", attr_name, sizeof("meta")) == 0) {
		parse_rule_meta(e, r);
	} else if (strncmp("counter", attr_name, sizeof("counter")) == 0) {
		parse_rule_counter(e, r);
	} else if (strncmp("payload", attr_name, sizeof("payload")) == 0) {
		parse_rule_payload(e, r);
	} else if (strncmp("immediate", attr_name, sizeof("immediate")) == 0) {
		parse_rule_immediate(e, r);
	} else {
		log_debug("unknown attr: %s\n", attr_name);
	}

	return MNL_CB_OK;
}

static void
rule_free(rule_t *r)
{
	free(r->desc);
	free(r->table);
	free(r->chain);
	free(r);
}

struct table_cb_data {
	const char * table;
	const char * chain;
	enum rule_type type;
	int alloc_failed;
	rule_t * captured;	/* capture : the parsed rule, not put in a list */
	int capture;
};

/* callback.
 * return values :
 *   MNL_CB_ERROR : an error has occurred. Stop callback runqueue.
 *   MNL_CB_STOP : top callback runqueue.
 *   MNL_CB_OK : no problems has occurred.
 */
static int
table_cb(const struct nlmsghdr *nlh, void *data)
{
	int result = MNL_CB_OK;
	struct nftnl_rule *rule;
	struct nftnl_expr_iter *itr;
#define CB_DATA(field) ((struct table_cb_data *)data)->field

	syslog(LOG_DEBUG, "table_cb(%p, %p) %s %s %d", nlh, data, CB_DATA(table), CB_DATA(chain), CB_DATA(type));
	rule = nftnl_rule_alloc();
	if (rule == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		CB_DATA(alloc_failed) = 1;
		return MNL_CB_OK;
	}
	if (nftnl_rule_nlmsg_parse(nlh, rule) < 0) {
		log_error("nftnl_rule_nlmsg_parse FAILED");
		CB_DATA(alloc_failed) = 1;
	} else {
		rule_t *r = malloc(sizeof(rule_t));
		if (r == NULL) {
			syslog(LOG_ERR, "%s: failed to allocate %u bytes",
			       "table_cb", (unsigned)sizeof(rule_t));
			CB_DATA(alloc_failed) = 1;
		} else {
			const char *chain;

			memset(r, 0, sizeof(rule_t));

			chain = nftnl_rule_get_str(rule, NFTNL_RULE_CHAIN);
			if (strcmp(chain, nft_prerouting_chain) == 0 ||
				strcmp(chain, nft_postrouting_chain) == 0 ||
				strcmp(chain, nft_forward_chain) == 0) {
				r->table = strdup(nftnl_rule_get_str(rule, NFTNL_RULE_TABLE));
				r->chain = strdup(chain);
				if (r->table == NULL || r->chain == NULL) {
					syslog(LOG_ERR, "%s: strdup() failed", "table_cb");
					free(r->table);
					free(r->chain);
					free(r);
					nftnl_rule_free(rule);
					CB_DATA(alloc_failed) = 1;
					return MNL_CB_OK;
				}
				r->family = nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY);
				if (nftnl_rule_is_set(rule, NFTNL_RULE_USERDATA)) {
					const char *descr;
					descr = (const char *) nftnl_rule_get_data(rule, NFTNL_RULE_USERDATA,
															 &r->desc_len);
					if (r->desc_len > 0) {
						r->desc = malloc(r->desc_len + 1);
						if (r->desc != NULL) {
							memcpy(r->desc, descr, r->desc_len);
							r->desc[r->desc_len] = '\0';
						} else {
							syslog(LOG_ERR, "failed to allocate %u bytes for desc", r->desc_len);
						}
					}
				}

				r->handle = nftnl_rule_get_u64(rule, NFTNL_RULE_HANDLE);
				r->type = CB_DATA(type);

				itr = nftnl_expr_iter_create(rule);
				if (itr == NULL) {
					syslog(LOG_ERR, "%s: nftnl_expr_iter_create() FAILED",
					       "table_cb");
				} else {
					struct nftnl_expr *expr;

					while ((expr = nftnl_expr_iter_next(itr)) != NULL) {
						rule_expr_cb(expr, r);
					}
					nftnl_expr_iter_destroy(itr);
				}

				if (CB_DATA(capture)) {
					/* the echo of a rule we sent : nft_send_rule() files it */
					if (CB_DATA(captured) == NULL) {
						CB_DATA(captured) = r;
						r = NULL;
					} else {
						rule_free(r);
						r = NULL;
					}
				} else
				switch (r->type) {
				case RULE_NAT:
					switch (r->nat_type) {
					case NFT_NAT_SNAT:
						LIST_INSERT_HEAD(&head_peer, r, entry);
						r = NULL;
						break;
					case NFT_NAT_DNAT:
						LIST_INSERT_HEAD(&head_redirect, r, entry);
						r = NULL;
						break;
					default:
						syslog(LOG_WARNING, "unknown nat type %d", r->nat_type);
					}
					break;

				case RULE_FILTER:
					LIST_INSERT_HEAD(&head_filter, r, entry);
					r = NULL;
					break;

				default:
					syslog(LOG_WARNING, "unknown rule type %d", r->type);
					break;
				}
			} else {
				syslog(LOG_WARNING, "unknown chain '%s'", chain);
			}
			if (r != NULL) {
				rule_free(r);
			}
		}
	}
	nftnl_rule_free(rule);
	return result;
}
#undef CB_DATA

static void nft_delete_batch_flush(void);

int
refresh_nft_cache_filter(void)
{
	if (rule_list_filter_validate != RULE_CACHE_VALID) {
		if (refresh_nft_cache(&head_filter, nft_table, nft_forward_chain, nft_ipv4_family, RULE_FILTER) < 0)
			return -1;
		rule_list_filter_validate = RULE_CACHE_VALID;
	}
	return 0;
}

int
refresh_nft_cache_peer(void)
{
	if (rule_list_peer_validate != RULE_CACHE_VALID) {
		if (refresh_nft_cache(&head_peer, nft_nat_table, nft_postrouting_chain, nft_nat_family, RULE_NAT) < 0)
			return -1;
		rule_list_peer_validate = RULE_CACHE_VALID;
	}
	return 0;
}

int
refresh_nft_cache_redirect(void)
{
	if (rule_list_redirect_validate != RULE_CACHE_VALID) {
		if (refresh_nft_cache(&head_redirect, nft_nat_table, nft_prerouting_chain, nft_nat_family, RULE_NAT) < 0)
			return -1;
		rule_list_redirect_validate = RULE_CACHE_VALID;
	}
	return 0;
}

void
flush_nft_cache(struct rule_list *head)
{
	rule_t *p1, *p2;

	p1 = LIST_FIRST(head);
	while (p1 != NULL) {
		p2 = (rule_t *)LIST_NEXT(p1, entry);
		if (p1->desc != NULL) {
			free(p1->desc);
		}
		if (p1->table != NULL) {
			free(p1->table);
		}
		if (p1->chain != NULL) {
			free(p1->chain);
		}
		free(p1);
		p1 = p2;
	}
	LIST_INIT(head);
}

/*
 * return -1 in case of error, 0 if OK
 */
int
refresh_nft_cache(struct rule_list *head, const char *table, const char *chain, uint32_t family, enum rule_type type)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct table_cb_data data;
	rule_t **deleted = deleted_slot(head);
	struct nftnl_rule *rule;
	int ret;
	ssize_t n;

	if (mnl_sock == NULL) {
		log_error("netlink not connected");
		return -1;
	}
	/* the dump must not bring back rules which are waiting to be deleted */
	nft_delete_batch_flush();
	flush_nft_cache(head);
	if (*deleted != NULL) {
		rule_free(*deleted);
		*deleted = NULL;
	}

	rule = nftnl_rule_alloc();
	if (rule == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return -1;
	}

	mnl_seq = time(NULL);
	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
					NLM_F_DUMP, mnl_seq);
	nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table);
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_nlmsg_build_payload(nlh, rule);
	nftnl_rule_free(rule);

	if (mnl_socket_sendto(mnl_sock, nlh, nlh->nlmsg_len) < 0) {
		log_error("mnl_socket_sendto() FAILED: %m");
		return -1;
	}

	memset(&data, 0, sizeof(data));	/* not capture : file the rules */
	data.table = table;
	data.chain = chain;
	data.type = type;
	do {
		n = mnl_socket_recvfrom(mnl_sock, buf, sizeof(buf));
		if (n < 0) {
			syslog(LOG_ERR, "%s: mnl_socket_recvfrom: %m",
			       "refresh_nft_cache");
			return -1;
		} else if (n == 0) {
			break;
		}
		/* https://git.netfilter.org/libmnl/tree/src/callback.c#n48 */
		errno = 0;
		ret = mnl_cb_run(buf, n, mnl_seq, mnl_portid, table_cb, &data);
		if (ret <= -1 /*== MNL_CB_ERROR*/) {
			syslog(LOG_ERR, "%s: mnl_cb_run returned %d: %m",
			       "refresh_nft_cache", ret);
			return -1;
		}
	} while(ret >= 1 /*== MNL_CB_OK*/);
	/* ret == MNL_CB_STOP */

	if (data.alloc_failed) {
		/* the dump was read to the end, but the cache is incomplete */
		syslog(LOG_ERR, "%s: rule cache refresh incomplete", "refresh_nft_cache");
		flush_nft_cache(head);
		return -1;
	}
	return 0;
}

static void
expr_add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
                 uint32_t offset, uint32_t len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("payload");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "payload");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

	nftnl_rule_add_expr(r, e);
}

static void
expr_add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
	     const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "cmp");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

#ifdef ENABLE_NFT_RULE_COUNTER
static void
expr_add_counter(struct nftnl_rule *r)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("counter");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "counter");
		return;
	}

	nftnl_rule_add_expr(r, e);
}
#endif

static void
expr_add_meta(struct nftnl_rule *r, uint32_t meta_key, uint32_t dreg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("meta");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "meta");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, meta_key);
	nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);

	nftnl_rule_add_expr(r, e);
}

/*
 * Add a "meta nfproto == <nfproto>" match.
 * The rules built in this file compare raw network-header payload at fixed
 * IPv4 (or IPv6) offsets. When the rule lives in an NFPROTO_INET table (the
 * default nft_*_family, as used by OpenWrt's fw4), that table is also walked
 * for packets of the other address family, where those offsets point at
 * unrelated, sender-chosen bytes. Without a family match the rule can then
 * match the wrong family. This pins the rule to its intended family.
 * It is only needed (and only valid) in an inet table; for an ip/ip6 table
 * the family is already implied, so emit nothing there.
 */
static void
expr_add_nfproto(struct nftnl_rule *r, uint8_t nfproto)
{
	uint8_t family = (uint8_t)nftnl_rule_get_u32(r, NFTNL_RULE_FAMILY);

	if (family != NFPROTO_INET)
		return;

	expr_add_meta(r, NFT_META_NFPROTO, NFT_REG_1);
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &nfproto, sizeof(uint8_t));
}

static void
expr_set_reg_val_u32(struct nftnl_rule *r, enum nft_registers dreg, uint32_t val)
{
	struct nftnl_expr *e;
	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "immediate");
		return;
	}
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DATA, val);
	nftnl_rule_add_expr(r, e);
}

static void
expr_set_reg_val_u16(struct nftnl_rule *r, enum nft_registers dreg, uint16_t val)
{
	struct nftnl_expr *e;
	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "immediate");
		return;
	}
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, dreg);
	nftnl_expr_set_u16(e, NFTNL_EXPR_IMM_DATA, val);
	nftnl_rule_add_expr(r, e);
}

static void
expr_set_reg_verdict(struct nftnl_rule *r, uint32_t val)
{
	struct nftnl_expr *e;
	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "immediate");
		return;
	}
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, val);
	nftnl_rule_add_expr(r, e);
}

static void
expr_add_nat(struct nftnl_rule *r, uint32_t t, uint32_t family,
	     in_addr_t addr_min, uint16_t proto_min, uint32_t flags)
{
	struct nftnl_expr *e;
	UNUSED(flags);

	e = nftnl_expr_alloc("nat");
	if (e == NULL) {
		expr_alloc_failed = 1;
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "nat");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_TYPE, t);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_FAMILY, family);

	/* To IP Address */
	expr_set_reg_val_u32(r, NFT_REG_1, (uint32_t)addr_min);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN, NFT_REG_1);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MAX, NFT_REG_1);
	/* To Port */
	expr_set_reg_val_u16(r, NFT_REG_2, proto_min);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MIN, NFT_REG_2);
	nftnl_expr_set_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MAX, NFT_REG_2);

	nftnl_rule_add_expr(r, e);
}

struct nftnl_rule *
rule_set_snat(uint8_t family, uint8_t proto,
	      in_addr_t rhost, unsigned short rport,
	      in_addr_t ehost, unsigned short eport,
	      in_addr_t ihost, unsigned short iport,
	      const char *descr,
	      const char *handle)
{
	struct nftnl_rule *r = NULL;
	uint16_t dport, sport;
	UNUSED(handle);

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, nft_nat_table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, nft_postrouting_chain);

	if (descr != NULL && *descr != '\0') {
		uint32_t len = strlen(descr);
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, MIN(len, NFTNL_RULE_USERDATA_MAX_LEN));
	}

	/* Family: these IPv4 offsets must not be evaluated against IPv6 packets
	 * when the rule lives in an inet table. */
	expr_add_nfproto(r, NFPROTO_IPV4);

	/* Destination IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, daddr), sizeof(uint32_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &rhost, sizeof(uint32_t));

	/* Source IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, saddr), sizeof(in_addr_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &ihost, sizeof(in_addr_t));

	/* Protocol */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, protocol), sizeof(uint8_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

	/* Source and Destination Port of Protocol */
	if (proto == IPPROTO_TCP) {
		/* Destination Port */
		dport = htons(rport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

		/* Source Port */
		sport = htons(iport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, source), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
	} else if (proto == IPPROTO_UDP) {
		/* Destination Port */
		dport = htons(rport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

		/* Source Port */
		sport = htons(iport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, source), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
	}

	expr_add_nat(r, NFT_NAT_SNAT, NFPROTO_IPV4, ehost, htons(eport), 0);

	debug_rule(r);

	return r;
}

struct nftnl_rule *
rule_set_dnat(uint8_t family, const char * ifname, uint8_t proto,
	      in_addr_t rhost, unsigned short eport,
	      in_addr_t ihost, unsigned short iport,
	      const char *descr,
	      const char *handle)
{
	struct nftnl_rule *r = NULL;
	uint16_t dport;
	uint64_t handle_num;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, nft_nat_table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, nft_prerouting_chain);

	if (descr != NULL && *descr != '\0') {
		uint32_t len = strlen(descr);
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, MIN(len, NFTNL_RULE_USERDATA_MAX_LEN));
	}

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

#ifdef USE_IFNAME_IN_RULES
	if (ifname != NULL) {
		uint32_t if_idx;
		if_idx = (uint32_t)if_nametoindex(ifname);
		expr_add_meta(r, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &if_idx,
			     sizeof(uint32_t));
	}
#endif

	/* Family: these IPv4 offsets must not be evaluated against IPv6 packets
	 * when the rule lives in an inet table. */
	expr_add_nfproto(r, NFPROTO_IPV4);

	/* Source IP */
	if (rhost != 0) {
		expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		                 offsetof(struct iphdr, saddr), sizeof(in_addr_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &rhost, sizeof(in_addr_t));
	}

	/* Protocol */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, protocol), sizeof(uint8_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

	if (proto == IPPROTO_TCP) {
		dport = htons(eport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));
	} else if (proto == IPPROTO_UDP) {
		dport = htons(eport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));
	}

#ifdef ENABLE_NFT_RULE_COUNTER
	/* Counter */
	expr_add_counter(r);
#endif

	expr_add_nat(r, NFT_NAT_DNAT, NFPROTO_IPV4, ihost, htons(iport), 0);

	debug_rule(r);

	return r;
}

struct nftnl_rule *
rule_set_filter(uint8_t family, const char * ifname, uint8_t proto,
		in_addr_t rhost, in_addr_t iaddr,
		unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	struct nftnl_rule *r = NULL;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	r = rule_set_filter_common(r, family, ifname, proto, eport, iport, rport, descr, handle);

	/* Family: in an inet table the IPv4 payload offsets below would also be
	 * evaluated against IPv6 packets, so constrain to IPv4 first. */
	expr_add_nfproto(r, NFPROTO_IPV4);

	/* Destination IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, daddr), sizeof(uint32_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &iaddr, sizeof(uint32_t));

	/* Source IP */
	if (rhost != 0) {
		expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		                 offsetof(struct iphdr, saddr), sizeof(in_addr_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &rhost,
			     sizeof(in_addr_t));
	}

	/* Protocol */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, protocol), sizeof(uint8_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

	expr_set_reg_verdict(r, NF_ACCEPT);

	debug_rule(r);

	return r;
}

/*
 * Create the IP6 filter rule
 * called by add_pinhole() and update_pinhole()
 * eport is always 0
 * iport is the destination port of the filter rule
 * rport is the (optional) source port of the rule
 */
struct nftnl_rule *
rule_set_filter6(uint8_t family, const char * ifname, uint8_t proto,
		struct in6_addr *rhost6, struct in6_addr *iaddr6,
		unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	struct nftnl_rule *r = NULL;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	r = rule_set_filter_common(r, family, ifname, proto, eport, iport, rport, descr, handle);

	/* Family: mirror of the IPv4 case. In an inet table, constrain to IPv6
	 * so these offsets are not evaluated against IPv4 packets. */
	expr_add_nfproto(r, NFPROTO_IPV6);

	/* Destination IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct ipv6hdr, daddr), sizeof(struct in6_addr));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, iaddr6, sizeof(struct in6_addr));

	/* Source IP */
	if (rhost6) {
		expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
		                 offsetof(struct ipv6hdr, saddr), sizeof(struct in6_addr));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, rhost6, sizeof(struct in6_addr));
	}

	/* Protocol */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct ipv6hdr, nexthdr), sizeof(uint8_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

	expr_set_reg_verdict(r, NF_ACCEPT);

	debug_rule(r);

	return r;
}

/*
 * Create common parts for the filter rules (IPv4 or IPv6)
 * eport is ignored
 * iport is the destination port of the filter rule
 * rport is the (optional) source port of the rule
 */
struct nftnl_rule *
rule_set_filter_common(struct nftnl_rule *r, uint8_t family, const char * ifname,
		uint8_t proto, unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	uint16_t dport, sport;
	uint64_t handle_num;
	UNUSED(eport);

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, nft_forward_chain);

	if (descr != NULL && *descr != '\0') {
		uint32_t len = strlen(descr);
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, MIN(len, NFTNL_RULE_USERDATA_MAX_LEN));
	}

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

#ifdef USE_IFNAME_IN_RULES
	if (ifname != NULL) {
		uint32_t if_idx;
		if_idx = (uint32_t)if_nametoindex(ifname);
		expr_add_meta(r, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &if_idx,
			     sizeof(uint32_t));
	}
#endif

	/* Destination Port */
	dport = htons(iport);
	if (proto == IPPROTO_TCP) {
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, dest), sizeof(uint16_t));
	} else if (proto == IPPROTO_UDP) {
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, dest), sizeof(uint16_t));
	}
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

	/* Source Port */
	if (rport != 0) {
		sport = htons(rport);
		if (proto == IPPROTO_TCP) {
			expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
			                 offsetof(struct tcphdr, source), sizeof(uint16_t));
		} else if (proto == IPPROTO_UDP) {
			expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
			                 offsetof(struct udphdr, source), sizeof(uint16_t));
		}
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
	}

	return r;
}

struct nftnl_rule *
rule_del_handle(rule_t *rule)
{
	struct nftnl_rule *r = NULL;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	if (rule->type == RULE_NAT) {
		// NAT Family is not chain/rule family
		nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, nft_nat_family);
	} else {
		nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, rule->family);
	}

	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, rule->table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, rule->chain);
	nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, rule->handle);

	return r;
}

static void
nft_mnl_batch_put(char *buf, uint16_t type, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = seq;

	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_INET;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = NFNL_SUBSYS_NFTABLES;
}

static int send_batch_cb(struct mnl_nlmsg_batch *batch, mnl_cb_t cb, void *cb_data);

/* the messages the kernel sends back for a rule sent with NLM_F_ECHO : the
 * rule, and the generation (NFT_MSG_NEWGEN), which is not a rule (libnftnl
 * aborts on parsing it as one) */
static int
rule_echo_cb(const struct nlmsghdr *nlh, void *data)
{
	if (NFNL_MSG_TYPE(nlh->nlmsg_type) != NFT_MSG_NEWRULE)
		return MNL_CB_OK;
	return table_cb(nlh, data);
}

/* Take a deleted rule out of the cache. Its callers may still read the entry
 * and follow its next pointer (LIST_REMOVE leaves that pointer as it is), so
 * the entry is kept until the next deletion from the same list. Returns 0 if
 * the rule is not in the list. */
static int
rule_cache_remove(struct rule_list *head, rule_t **deleted, uint64_t handle)
{
	rule_t *p;

	LIST_FOREACH(p, head, entry) {
		if (p->handle == handle) {
			LIST_REMOVE(p, entry);
			if (*deleted != NULL)
				rule_free(*deleted);
			*deleted = p;
			return 1;
		}
	}
	return 0;
}

/* Deletions between nft_delete_batch_begin() and nft_delete_batch_end() go to
 * the kernel in one transaction : a commit copies the rule pointers of the
 * chain it changes, and with one commit per rule that was most of the time of
 * an expiry. The FILTER policies of these rules are removed after the commit,
 * as a mapping stays filtered until its rules are gone. */
#define NFT_DELETE_BATCH_MAX	256

static void
rule_cache_invalidate_all(void)
{
	rule_list_filter_validate = RULE_CACHE_INVALID;
	rule_list_redirect_validate = RULE_CACHE_INVALID;
	rule_list_peer_validate = RULE_CACHE_INVALID;
}

#define NFT_DELETE_BATCH_BUF	(128 * 1024)
/* a new rule is much larger than a deletion */
#define NFT_ADD_BATCH_MAX	128

struct delete_item {
	struct nftnl_rule *rule;
	uint16_t cmd;		/* NFT_MSG_DELRULE, or NFT_MSG_NEWRULE in a restore */
	uint16_t flags;		/* of a new rule */
	enum rule_chain_type chain;
	int done;		/* the rule is gone from the kernel */
	int is_peer;		/* drop this PEER lease once the rule is gone */
	int is_redirect;	/* drop this timestamp once the rule is gone */
	in_addr_t iaddr, raddr;
	unsigned short iport, rport;
	unsigned short eport;
	int proto;
};

/* The rules of a mapping, then its policy : the items from the end of the
 * previous policy to rule_end are the rules of this one. */
struct delete_policy {
	struct in6_addr address;
	unsigned short port;
	unsigned char protocol;
	unsigned int rule_end;
	int rule_failed;	/* a rule of it failed in an earlier flush */
};

static int delete_batch_active;
static int delete_batch_adds;		/* new rules are queued too (a restore) */
static int delete_batch_failed;		/* since nft_delete_batch_begin() */
static int delete_batch_group_failed;	/* of the mapping being queued */
static struct delete_item delete_batch_items[NFT_DELETE_BATCH_MAX];
static unsigned int delete_batch_count;
static struct delete_policy delete_batch_policies[NFT_DELETE_BATCH_MAX];
static unsigned int delete_batch_policy_count;

void
nft_delete_batch_begin(void)
{
	delete_batch_active = 1;
	delete_batch_failed = 0;
	delete_batch_group_failed = 0;
}

/* a queued redirect rule : its timestamp goes when the rule is gone.
 * returns 0 if there is no batch (the caller removes the timestamp) */
int
nft_delete_batch_redirect(unsigned short eport, int proto)
{
	struct delete_item *d;

	if (!delete_batch_active)
		return 0;
	d = &delete_batch_items[delete_batch_count - 1];
	d->is_redirect = 1;
	d->eport = eport;
	d->proto = proto;
	return 1;
}

/* a queued PEER rule : its lease goes when the rule is gone.
 * returns 0 if there is no batch (the caller removes the lease) */
int
nft_delete_batch_peer(in_addr_t iaddr, unsigned short iport,
                      in_addr_t raddr, unsigned short rport, int proto)
{
	struct delete_item *d;

	if (!delete_batch_active)
		return 0;
	d = &delete_batch_items[delete_batch_count - 1];
	d->is_peer = 1;
	d->iaddr = iaddr;
	d->iport = iport;
	d->raddr = raddr;
	d->rport = rport;
	d->proto = proto;
	return 1;
}

/* Send what is queued. If the kernel refuses the transaction nothing of it was
 * done : each rule is then sent alone, so one rule which is gone already does
 * not keep the others, and only what is gone completes (a lease, a policy).
 * What is left is tried again by the next expiry. */
static void
nft_delete_batch_flush(void)
{
	static char buf[NFT_DELETE_BATCH_BUF * 2];
	struct mnl_nlmsg_batch *batch;
	struct nlmsghdr *nlh = NULL;
	unsigned int i, r = 0;
	int active = delete_batch_active;
	int result = -1;

	if (delete_batch_count == 0 && delete_batch_policy_count == 0)
		return;
	delete_batch_active = 0;	/* the calls below are not queued */
	if (delete_batch_count > 0 &&
	    (batch = start_batch(buf, NFT_DELETE_BATCH_BUF)) != NULL) {
		for (i = 0; i < delete_batch_count; i++) {
			struct nftnl_rule *rule = delete_batch_items[i].rule;
			if (i > 0 && !mnl_nlmsg_batch_next(batch)) {
				/* it does not fit : the last message, with the
				 * ACK, would not be sent, and nothing would ever
				 * answer. Send the rules alone. */
				nlh = NULL;
				break;
			}
			nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			                                 delete_batch_items[i].cmd,
			                                 nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY),
			                                 delete_batch_items[i].flags, mnl_seq++);
			nftnl_rule_nlmsg_build_payload(nlh, rule);
		}
		if (nlh != NULL) {
			/* one acknowledgement, after the complete transaction */
			nlh->nlmsg_flags |= NLM_F_ACK;
			result = send_batch(batch);
		} else {
			mnl_nlmsg_batch_stop(batch);
		}
	}
	for (i = 0; i < delete_batch_count; i++) {
		struct delete_item *d = &delete_batch_items[i];
		if (result >= 0) {
			nftnl_rule_free(d->rule);
			d->done = 1;
		} else {
			uint16_t cmd = d->cmd;
			d->done = nft_send_rule(d->rule, cmd, d->chain) >= 0 ||
			          (cmd == NFT_MSG_DELRULE && errno == ENOENT);
		}
		if (!d->done)
			delete_batch_failed = 1;
		else if (d->is_peer)
			peer_lease_remove(d->iaddr, d->iport, d->raddr, d->rport, d->proto);
		else if (d->is_redirect)
			nft_redirect_removed(d->eport, d->proto);
	}
	/* the cache has lost rules which may still be there */
	if (result < 0)
		rule_cache_invalidate_all();
	/* a mapping stays filtered if one of its rules is left */
	for (i = 0; i < delete_batch_policy_count; i++) {
		const struct delete_policy *p = &delete_batch_policies[i];
		int complete = !p->rule_failed;
		for (; r < p->rule_end; r++)
			complete = complete && delete_batch_items[r].done;
		if (complete && nft_pcp_filter_delete(&p->address, p->port, p->protocol) < 0)
			delete_batch_failed = 1;
	}
	/* rules of a mapping whose policy is not queued yet */
	for (; r < delete_batch_count; r++) {
		if (!delete_batch_items[r].done && !delete_batch_items[r].is_peer)
			delete_batch_group_failed = 1;
	}
	delete_batch_count = 0;
	delete_batch_policy_count = 0;
	delete_batch_active = active;
}

int
nft_delete_batch_end(void)
{
	nft_delete_batch_flush();
	delete_batch_active = 0;
	/* the new rules were sent without an echo : they are not in the cache */
	if (delete_batch_adds)
		rule_cache_invalidate_all();
	delete_batch_adds = 0;
	return delete_batch_failed ? -1 : 0;
}

/* The restore of the PCP lease file : new rules are queued too, and go to the
 * kernel a batch at a time. nft_delete_batch_end() ends it. The cache does not
 * have them until then : each restored mapping has a key of its own, so the
 * lookups of the restore do not need them, and a dump per batch would be slow. */
void
nft_restore_batch_begin(void)
{
	nft_delete_batch_begin();
	delete_batch_adds = 1;
}

/* Send a rule change and keep the cache of its chain valid when it can :
 * a new rule is sent with NLM_F_ECHO and the kernel's copy of it (with its
 * handle) goes into the cache, so the next lookup does not dump the chain
 * again (a dump per request made N requests cost O(N^2)). A replaced rule is
 * updated in place in the cache. A deleted rule leaves the cache, see
 * rule_cache_remove(). An error or a missing echo invalidate the cache as
 * before. */
int
nft_send_rule(struct nftnl_rule * rule, uint16_t cmd, enum rule_chain_type chain_type)
{
	int result = -1;
	uint16_t flags = NLM_F_CREATE | NLM_F_ACK;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE*2];
	struct table_cb_data echo;
	struct rule_list *head;
	uint32_t *validate;
	rule_t **deleted;
	uint64_t old_handle = 0;
	uint64_t del_handle = 0;
	int saved_errno = 0;
	int replace = 0;

	switch (chain_type) {
	case RULE_CHAIN_FILTER:
		head = &head_filter;
		validate = &rule_list_filter_validate;
		break;
	case RULE_CHAIN_PEER:
		head = &head_peer;
		validate = &rule_list_peer_validate;
		break;
	default:
		head = &head_redirect;
		validate = &rule_list_redirect_validate;
		break;
	}
	deleted = deleted_slot(head);
	if (rule == NULL)
		return -1;
	if (cmd == NFT_MSG_DELRULE) {
		del_handle = nftnl_rule_get_u64(rule, NFTNL_RULE_HANDLE);
		if (delete_batch_active) {
			if (delete_batch_count == NFT_DELETE_BATCH_MAX)
				nft_delete_batch_flush();	/* a failure is kept for nft_delete_batch_end() */
			memset(&delete_batch_items[delete_batch_count], 0,
			       sizeof(delete_batch_items[0]));
			delete_batch_items[delete_batch_count].cmd = NFT_MSG_DELRULE;
			delete_batch_items[delete_batch_count].rule = rule;
			delete_batch_items[delete_batch_count++].chain = chain_type;
			if (*validate == RULE_CACHE_VALID &&
			    !rule_cache_remove(head, deleted, del_handle))
				*validate = RULE_CACHE_INVALID;
			return 0;
		}
	}
	/* PEER SNAT must run before a gateway's catch-all masquerade rule. */
	if (chain_type != RULE_CHAIN_PEER)
		flags |= NLM_F_APPEND;
	if (cmd == NFT_MSG_NEWRULE && nftnl_rule_is_set(rule, NFTNL_RULE_HANDLE)) {
		flags = NLM_F_REPLACE | NLM_F_ACK;
		replace = 1;
		old_handle = nftnl_rule_get_u64(rule, NFTNL_RULE_HANDLE);
	}
	if (cmd == NFT_MSG_NEWRULE && delete_batch_active && delete_batch_adds && !replace) {
		if (delete_batch_count >= NFT_ADD_BATCH_MAX)
			nft_delete_batch_flush();
		memset(&delete_batch_items[delete_batch_count], 0,
		       sizeof(delete_batch_items[0]));
		delete_batch_items[delete_batch_count].cmd = NFT_MSG_NEWRULE;
		delete_batch_items[delete_batch_count].flags = flags & ~NLM_F_ACK;
		delete_batch_items[delete_batch_count].rule = rule;
		delete_batch_items[delete_batch_count++].chain = chain_type;
		return 0;
	}
	if (cmd == NFT_MSG_NEWRULE)
		flags |= NLM_F_ECHO;

	memset(&echo, 0, sizeof(echo));
	echo.table = "";
	echo.chain = "";
	echo.type = chain_type == RULE_CHAIN_FILTER ? RULE_FILTER : RULE_NAT;
	echo.capture = 1;

	batch = start_batch(buf, MNL_SOCKET_BUFFER_SIZE);
	if (batch != NULL)
	{
		nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
		                                 cmd,
		                                 nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY),
		                                 flags,
		                                 mnl_seq++);

		nftnl_rule_nlmsg_build_payload(nlh, rule);
		nftnl_rule_free(rule);

		result = send_batch_cb(batch, cmd == NFT_MSG_NEWRULE ? rule_echo_cb : NULL, &echo);
		saved_errno = errno;
		if (result < 0) {
			syslog(LOG_ERR, "%s(%p, %d, %d) send_batch failed %d",
			       "nft_send_rule", rule, (int)cmd, (int)chain_type, result);
		}
	} else {
		nftnl_rule_free(rule);
	}

	if (result >= 0 && cmd == NFT_MSG_DELRULE && *validate == RULE_CACHE_VALID) {
		if (!rule_cache_remove(head, deleted, del_handle))
			*validate = RULE_CACHE_INVALID;
	} else if (result < 0 || cmd != NFT_MSG_NEWRULE || echo.captured == NULL ||
	    echo.alloc_failed || *validate != RULE_CACHE_VALID) {
		*validate = RULE_CACHE_INVALID;	/* dumped again at the next lookup */
		if (echo.captured != NULL)
			rule_free(echo.captured);
	} else if (replace) {
		rule_t *p;
		LIST_FOREACH(p, head, entry) {
			if (p->handle == old_handle)
				break;
		}
		if (p == NULL) {
			*validate = RULE_CACHE_INVALID;
			rule_free(echo.captured);
		} else {
			/* the entry stays where it is in the list */
			rule_t *n = echo.captured;
			free(p->desc);
			free(p->table);
			free(p->chain);
			n->entry = p->entry;
			*p = *n;
			free(n);
		}
	} else {
		/* a dump lists the chain backwards (LIST_INSERT_HEAD), so a rule
		 * appended to the chain goes first in the list. The PEER rules go
		 * first in their chain: they are only looked up by their key. */
		LIST_INSERT_HEAD(head, echo.captured, entry);
	}
	errno = saved_errno;
	return result;
}

/* the next lookup reads the redirect rules and their counters from the kernel */
void
nft_redirect_cache_invalidate(void)
{
	rule_list_redirect_validate = RULE_CACHE_INVALID;
}

int
table_op( enum nf_tables_msg_types op, uint16_t family, const char * name)
{
	int result;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE*2];

	struct nftnl_table *table;

	// log_debug("(%d, %d, %s)", op, family, name);

	table = nftnl_table_alloc();
	if (table == NULL) {
		log_error("out of memory: %m");
		result = -1;
	} else {
		nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, family);
		nftnl_table_set_str(table, NFTNL_TABLE_NAME, name);

		batch = start_batch(buf, MNL_SOCKET_BUFFER_SIZE);
		if (batch == NULL) {
			log_error("out of memory: %m");
			result = -2;
		} else {
			nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			                                  op, family,
			                                  (op == NFT_MSG_NEWTABLE ? NLM_F_CREATE : 0) | NLM_F_ACK,
			                                  mnl_seq++);
			nftnl_table_nlmsg_build_payload(nlh, table);

			result = send_batch(batch);
			if (result < 0) {
				syslog(LOG_ERR, "%s(%d, %d, %s) send_batch failed %d",
				       "table_op", (int)op, (int)family, name, result);
			}
		}
		nftnl_table_free(table);
	}
	return result;
}

/*
 * return values :
 *  -2 : out of memory (nftnl_chain_alloc)
 *  -3 : out of memory (start batch)
 *  -4 : failed to build header
 */
int
chain_op(enum nf_tables_msg_types op, uint16_t family, const char * table,
		 const char * name, const char * type, uint32_t hooknum, signed int priority )
{
	int result = -1;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE*2];

	struct nftnl_chain *chain;

	// log_debug("(%d, %d, %s, %s, %s, %d, %d)", op, family, table, name, type, hooknum, priority);

	chain = nftnl_chain_alloc();
	if (chain == NULL) {
		log_error("out of memory: %m");
		result = -2;
	} else {
		nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
		nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table);
		nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, name);
		if (op == NFT_MSG_NEWCHAIN) {
			nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, type);
			nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, hooknum);
			nftnl_chain_set_s32(chain, NFTNL_CHAIN_PRIO, priority);
		}

		batch = start_batch(buf, MNL_SOCKET_BUFFER_SIZE);
		if (batch == NULL) {
			log_error("out of memory: %m");
			result = -3;
		} else {
			nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
			                                  op, family,
			                                  (op == NFT_MSG_NEWCHAIN ? NLM_F_CREATE : 0) | NLM_F_ACK,
			                                  mnl_seq++);
			if (nlh == NULL)
			{
				log_error("failed to build header: %m");
				result = -4;
			} else {
				nftnl_chain_nlmsg_build_payload(nlh, chain);

				result = send_batch(batch);
				if (result < 0) {
					syslog(LOG_ERR, "%s(%d, %d, %s, %s, %s, %u, %d) send_batch failed %d",
					       "chain_op", (int)op, (int)family, table, name, type,
						   hooknum, priority, result);
				}
			}
		}
		nftnl_chain_free(chain);
	}
	return result;
}

/**
 * the buffer that you have to use to store the batch must be double
 * of MNL_SOCKET_BUFFER_SIZE
 * @see https://www.netfilter.org/projects/libmnl/doxygen/html/group__batch.html
 */
struct mnl_nlmsg_batch *
start_batch(char *buf, size_t buf_size)
{
	struct mnl_nlmsg_batch *result;

	if (mnl_sock == NULL) {
		log_error("netlink not connected");
		return NULL;
	}
	mnl_seq = time(NULL);
	result = mnl_nlmsg_batch_start(buf, buf_size);
	if (result == NULL) {
		syslog(LOG_ERR, "%s: mnl_nlmsg_batch_start(%p, %lu) returned NULL",
		       "start_batch", buf, (unsigned long)buf_size);
		return NULL;
	}
	nft_mnl_batch_put(mnl_nlmsg_batch_current(result),
					  NFNL_MSG_BATCH_BEGIN, mnl_seq++);
	if (!mnl_nlmsg_batch_next(result)) {
		syslog(LOG_ERR, "%s: mnl_nlmsg_batch_next returned false", "start_batch");
	}
	return result;
}

/**
 * return codes :
 * 0  : OK
 * -1 : netlink not connected
 * -2 : mnl_socket_sendto() error
 * -3 : mnl_socket_recvfrom() error
 * -4 : mnl_cb_run() error
 */
int
send_batch(struct mnl_nlmsg_batch *batch)
{
	return send_batch_cb(batch, NULL, NULL);
}

/* send_batch() : cb is called for the messages the kernel sends back before
 * the acknowledgement (the echo of a rule sent with NLM_F_ECHO) */
static int
send_batch_cb(struct mnl_nlmsg_batch *batch, mnl_cb_t cb, void *cb_data)
{
	int ret;
	ssize_t n;
	char buf[MNL_SOCKET_BUFFER_SIZE];

	mnl_nlmsg_batch_next(batch);

	nft_mnl_batch_put(mnl_nlmsg_batch_current(batch), NFNL_MSG_BATCH_END, mnl_seq++);
	mnl_nlmsg_batch_next(batch);

	if (mnl_sock == NULL) {
		log_error("netlink not connected");
		return -1;
	}

	n = mnl_socket_sendto(mnl_sock, mnl_nlmsg_batch_head(batch),
	                      mnl_nlmsg_batch_size(batch));
	if (n == -1) {
		log_error("mnl_socket_sendto() FAILED: %m");
		return -2;
	}
	mnl_nlmsg_batch_stop(batch);

	do {
		n = mnl_socket_recvfrom(mnl_sock, buf, sizeof(buf));
		if (n == -1) {
			log_error("mnl_socket_recvfrom() FAILED: %m");
			return -3;
		} else if (n == 0) {
			break;
		}
		/* https://git.netfilter.org/libmnl/tree/src/callback.c#n48 */
		errno = 0;
		ret = mnl_cb_run(buf, n, 0, mnl_portid, cb, cb_data);
		if (ret <= -1 /*== MNL_CB_ERROR*/) {
			int saved_errno = errno;
			syslog(LOG_ERR, "%s: mnl_cb_run returned %d: %m",
			       "send_batch", ret);
			/* read what the kernel still sends for this batch (the other
			 * acknowledgements), so the next request on the socket does
			 * not get it as its own answer */
			while (recv(mnl_socket_get_fd(mnl_sock), buf, sizeof(buf),
			            MSG_DONTWAIT) > 0)
				;
			errno = saved_errno;	/* the callers look at the kernel's error */
			return -4;
		}
	} while (ret >= 1 /*== MNL_CB_OK*/);
	/* ret == MNL_CB_STOP */
	return 0;
}

/* The peers of a filtered mapping (see pcp_filter_install()) */
struct pcp_filter_policy {
	struct pcp_filter_policy *next;
	struct in6_addr address;
	unsigned short port;
	unsigned char protocol;
	char ifname[IFNAMSIZ];
	unsigned int count;
	int recovery_error;
	int seen_filtered;	/* recovery : in the filtered set */
	struct pcp_filter filters[PCP_FILTER_PEER_MAX];
};

struct pcp_filter_update {
	struct pcp_filter_policy *old;
	struct pcp_filter_policy *replacement;
	int unchanged;	/* same peers as before : nothing was installed */
};

/* does the policy p have the same peers, in the same order, on the same
 * interface as old (NULL : no peer) ? */
static int
pcp_filter_same(const struct pcp_filter_policy *p,
                const struct pcp_filter_policy *old)
{
	if (!old)
		return p->count == 0;
	return p->count == old->count &&
	       strcmp(p->ifname, old->ifname) == 0 &&
	       memcmp(p->filters, old->filters, p->count * sizeof(p->filters[0])) == 0;
}

/* The policies of the filtered mappings, in a hash table on (address, port,
 * protocol). They are read from the kernel once (pcp_filter_recover()), then
 * this table is authoritative : a mapping which is not in it has no filter. */
#define PCP_FILTER_HASH_SIZE 1024
static struct pcp_filter_policy *pcp_filter_policies[PCP_FILTER_HASH_SIZE];
static int pcp_filter_recovered;

static unsigned int
pcp_filter_bucket(const struct in6_addr *address, unsigned short port,
                  unsigned char protocol)
{
	unsigned int h = 2166136261u, i;
	for (i = 0; i < sizeof(address->s6_addr); ++i)
		h = (h ^ address->s6_addr[i]) * 16777619u;
	h = (h ^ port) * 16777619u;
	h = (h ^ protocol) * 16777619u;
	return h % PCP_FILTER_HASH_SIZE;
}

static struct pcp_filter_policy **
pcp_filter_find(const struct in6_addr *address, unsigned short port,
                unsigned char protocol)
{
	struct pcp_filter_policy **p;
	for (p = &pcp_filter_policies[pcp_filter_bucket(address, port, protocol)];
	     *p; p = &(*p)->next) {
		if ((*p)->port == port && (*p)->protocol == protocol &&
		    memcmp(&(*p)->address, address, sizeof(*address)) == 0)
			break;
	}
	return p;
}

/* The FILTER policies on the packet path (RFC 6887 section 13.3), see
 * PCP-DESIGN.md section 6c. Per IP version one base chain on the forward
 * hook, before the forward chain of miniupnpd, holds four rules, each with
 * ct direction original iifname <ext> :
 *   daddr . l4proto . dport . saddr . sport @pcp-filter-peer<v> accept
 *   daddr . l4proto . dport . saddr @pcp-filter-host<v> accept
 *   daddr . l4proto . dport . saddr . sport @pcp-filter-allow<v> accept
 *   daddr . l4proto . dport @pcp-filter-filtered<v> drop
 * A peer which is one host goes into one of the two hash sets, with its port
 * or for any port. The allow set holds the real prefixes as ranges : a large
 * range set is much slower to change than a hash set. The filtered set has
 * an element per filtered mapping. The elements carry no verdict, so a change
 * never makes the kernel validate the table again, and a packet costs at most
 * four lookups whatever the number of mappings.
 * An accept only ends this base chain : the packet still has to pass the
 * ordinary firewall. */
#define PCP_FILTER_BASE4	"pcp-filter-v4"
#define PCP_FILTER_BASE6	"pcp-filter-v6"
#define PCP_FILTER_ALLOW4	"pcp-filter-allow4"
#define PCP_FILTER_ALLOW6	"pcp-filter-allow6"
#define PCP_FILTER_FILTERED4	"pcp-filter-filtered4"
#define PCP_FILTER_FILTERED6	"pcp-filter-filtered6"
#define PCP_FILTER_PEER4	"pcp-filter-peer4"
#define PCP_FILTER_PEER6	"pcp-filter-peer6"
#define PCP_FILTER_HOST4	"pcp-filter-host4"
#define PCP_FILTER_HOST6	"pcp-filter-host6"
/* the sets of a family, in the order of the rules of the base chain */
enum pcp_filter_kind {
	PCP_SET_PEER,		/* one host, one port */
	PCP_SET_HOST,		/* one host, any port */
	PCP_SET_RANGE,		/* a prefix, one port or any port */
	PCP_SET_FILTERED,	/* the filtered mappings */
	PCP_SET_COUNT
};
#define PCP_SET_PEER_KINDS	PCP_SET_FILTERED	/* the sets which hold peers */
/* the types of the keys, for nft list : ipv4_addr (7) or ipv6_addr (8),
 * inet_proto (12), inet_service (13) */
#define T_ADDR(v4)		((v4) ? 7u : 8u)
#define PCP_FILTER_ALLOW_TYPE(v4)	((((((T_ADDR(v4) << 6) | 12u) << 6 | 13u) << 6 | T_ADDR(v4)) << 6) | 13u)
#define PCP_FILTER_HOST_TYPE(v4)	((((((T_ADDR(v4) << 6) | 12u) << 6) | 13u) << 6) | T_ADDR(v4))
#define PCP_FILTER_FILTERED_TYPE(v4)	((((T_ADDR(v4) << 6) | 12u) << 6) | 13u)
#define PCP_FILTER_KEY_MAX	44	/* 16 + 4 + 4 + 16 + 4 */
/* the base chain and the sets of a family are set up by the first install of
 * this process, again after an error or for another interface */
static int pcp_filter_dispatch_ready[2];	/* [v4] */
static char pcp_filter_dispatch_ifname[2][IFNAMSIZ];

/* the bulk load of the policies (nft_pcp_filter_bulk_begin()) : one transaction
 * which pcp_filter_install() adds to instead of sending its own */
static struct mnl_nlmsg_batch *pcp_filter_bulk;
static char *pcp_filter_bulk_buf;
static int pcp_filter_bulk_pending;

/* the next message of a batch : the previous one is ended first. The last
 * one is ended by send_batch() */
static void *
pcp_filter_batch_msg(struct mnl_nlmsg_batch *batch, int *pending)
{
	if (*pending)
		mnl_nlmsg_batch_next(batch);
	*pending = 1;
	return mnl_nlmsg_batch_current(batch);
}

static uint32_t
pcp_filter_alen(int v4)
{
	return v4 ? 4 : 16;
}

/* the address of a mapping or a peer as it is in the packet */
static const unsigned char *
pcp_filter_addr(const struct in6_addr *a, int v4)
{
	return a->s6_addr + (v4 ? 12 : 0);
}

/* daddr . l4proto . dport of a mapping, each field in 32 bit registers as
 * the lookup reads them. returns the length */
static uint32_t
pcp_filter_key_mapping(const struct pcp_filter_policy *policy, unsigned char *key)
{
	int v4 = IN6_IS_ADDR_V4MAPPED(&policy->address);
	uint32_t alen = pcp_filter_alen(v4);
	uint16_t port = htons(policy->port);
	memset(key, 0, alen + 8);
	memcpy(key, pcp_filter_addr(&policy->address, v4), alen);
	key[alen] = policy->protocol;
	memcpy(key + alen + 4, &port, 2);
	return alen + 8;
}

/* the start (high = 0) or the end of the range of a peer in the allow set :
 * the mapping, then the peer's prefix and port (any : 0-65535). returns the
 * length */
static uint32_t
pcp_filter_key_peer(const struct pcp_filter_policy *policy,
                    const struct pcp_filter *f, int high, unsigned char *key)
{
	int v4 = IN6_IS_ADDR_V4MAPPED(&policy->address);
	uint32_t alen = pcp_filter_alen(v4), off = pcp_filter_key_mapping(policy, key);
	struct in6_addr a = f->address;
	uint16_t port;
	unsigned int i, prefix = f->prefix;
	pcp_filter_mask(&a, prefix);
	if (high) {
		/* the host bits set */
		for (i = 0; i < 16; i++, prefix = prefix >= 8 ? prefix - 8 : 0)
			a.s6_addr[i] |= prefix >= 8 ? 0 : (unsigned char)(0xff >> prefix);
	}
	memset(key + off, 0, alen + 4);
	memcpy(key + off, pcp_filter_addr(&a, v4), alen);
	port = htons(f->port ? f->port : (high ? 0xffff : 0));
	memcpy(key + off + alen, &port, 2);
	return off + alen + 4;
}

/* the set which holds the peer f */
static enum pcp_filter_kind
pcp_filter_peer_kind(const struct pcp_filter *f)
{
	if (f->prefix != 128)
		return PCP_SET_RANGE;
	return f->port ? PCP_SET_PEER : PCP_SET_HOST;
}

/* the name of a set */
static const char *
pcp_filter_set_name(int v4, enum pcp_filter_kind kind)
{
	switch (kind) {
	case PCP_SET_PEER:
		return v4 ? PCP_FILTER_PEER4 : PCP_FILTER_PEER6;
	case PCP_SET_HOST:
		return v4 ? PCP_FILTER_HOST4 : PCP_FILTER_HOST6;
	case PCP_SET_RANGE:
		return v4 ? PCP_FILTER_ALLOW4 : PCP_FILTER_ALLOW6;
	default:
		return v4 ? PCP_FILTER_FILTERED4 : PCP_FILTER_FILTERED6;
	}
}

static uint32_t
pcp_filter_set_id(int v4, enum pcp_filter_kind kind)
{
	return (v4 ? 1 : 1 + PCP_SET_COUNT) + (uint32_t)kind;
}

/* add the peer f of policy to the set of its kind (a range has an end, the
 * key of a peer for any port has no port). returns <0 if out of memory */
static int pcp_filter_add_elem(struct nftnl_set *set, const unsigned char *key,
                               const unsigned char *end, uint32_t len);

static int
pcp_filter_add_peer(struct nftnl_set *set, const struct pcp_filter_policy *policy,
                    const struct pcp_filter *f)
{
	unsigned char key[PCP_FILTER_KEY_MAX], end[PCP_FILTER_KEY_MAX];
	enum pcp_filter_kind kind = pcp_filter_peer_kind(f);
	uint32_t len = pcp_filter_key_peer(policy, f, 0, key);
	if (kind == PCP_SET_RANGE) {
		pcp_filter_key_peer(policy, f, 1, end);
		return pcp_filter_add_elem(set, key, end, len);
	}
	return pcp_filter_add_elem(set, key, NULL, kind == PCP_SET_HOST ? len - 4 : len);
}

/* is the peer a inside the peer b (a narrower or equal prefix of it, with
 * the same port or b any port) ? */
static int
pcp_filter_inside(const struct pcp_filter *a, const struct pcp_filter *b)
{
	struct in6_addr x = a->address, y = b->address;
	if (b->prefix > a->prefix || (b->port != 0 && b->port != a->port))
		return 0;
	pcp_filter_mask(&x, b->prefix);
	pcp_filter_mask(&y, b->prefix);
	return memcmp(&x, &y, sizeof(x)) == 0;
}

/* the peers of a policy which are installed : not those inside an other one
 * of the policy, which add nothing (and which the kernel refuses, as their
 * range starts inside an element). in[k] is set for each one installed */
static void
pcp_filter_installed(const struct pcp_filter_policy *policy, unsigned char *in)
{
	unsigned int i, j;
	for (i = 0; i < policy->count; i++) {
		in[i] = 1;
		for (j = 0; j < policy->count && in[i]; j++) {
			if (j == i || !pcp_filter_inside(&policy->filters[i], &policy->filters[j]))
				continue;
			/* of two equal peers the first one is installed */
			if (!pcp_filter_inside(&policy->filters[j], &policy->filters[i]) || j < i)
				in[i] = 0;
		}
	}
}

static struct nftnl_set *
pcp_filter_set(int v4, enum pcp_filter_kind kind)
{
	struct nftnl_set *set = nftnl_set_alloc();
	if (!set)
		return NULL;
	nftnl_set_set_str(set, NFTNL_SET_TABLE, nft_table);
	nftnl_set_set_str(set, NFTNL_SET_NAME, pcp_filter_set_name(v4, kind));
	nftnl_set_set_u32(set, NFTNL_SET_FAMILY, v4 ? nft_ipv4_family : nft_ipv6_family);
	nftnl_set_set_u32(set, NFTNL_SET_ID, pcp_filter_set_id(v4, kind));
	return set;
}

/* the conditions of the rules of a base chain : the original direction,
 * the external interface */
static void
pcp_filter_rule_head(struct nftnl_rule *r, int v4, const char *ifname)
{
	struct nftnl_expr *ct;
	uint8_t direction = IP_CT_DIR_ORIGINAL;
	expr_add_nfproto(r, v4 ? NFPROTO_IPV4 : NFPROTO_IPV6);
	ct = nftnl_expr_alloc("ct");
	if (!ct) {
		expr_alloc_failed = 1;
		return;
	}
	nftnl_expr_set_u32(ct, NFTNL_EXPR_CT_KEY, NFT_CT_DIRECTION);
	nftnl_expr_set_u32(ct, NFTNL_EXPR_CT_DREG, NFT_REG_1);
	nftnl_rule_add_expr(r, ct);
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &direction, sizeof(direction));
	expr_add_meta(r, NFT_META_IIFNAME, NFT_REG_1);
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, ifname, strlen(ifname) + 1);
}

/* a rule of a base chain : a lookup of daddr . l4proto . dport and, for the
 * peers, . saddr and . sport, then accept or drop */
static struct nftnl_rule *
pcp_filter_dispatch_rule(int v4, enum pcp_filter_kind kind, const char *ifname)
{
	uint16_t family = v4 ? nft_ipv4_family : nft_ipv6_family;
	uint32_t alen = pcp_filter_alen(v4), reg = NFT_REG32_00;
	struct nftnl_rule *r = nftnl_rule_alloc();
	struct nftnl_expr *lookup;
	if (!r)
		return NULL;
	expr_alloc_failed = 0;
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(r, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, v4 ? PCP_FILTER_BASE4 : PCP_FILTER_BASE6);
	pcp_filter_rule_head(r, v4, ifname);
	/* the fields in consecutive 32 bit registers */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, reg,
	                 v4 ? offsetof(struct iphdr, daddr) : offsetof(struct ipv6hdr, daddr), alen);
	reg += alen / 4;
	expr_add_meta(r, NFT_META_L4PROTO, reg++);
	expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, reg++, 2, 2);
	if (kind != PCP_SET_FILTERED) {
		expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, reg,
		                 v4 ? offsetof(struct iphdr, saddr) : offsetof(struct ipv6hdr, saddr), alen);
		reg += alen / 4;
		if (kind != PCP_SET_HOST)
			expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, reg, 0, 2);
	}
	lookup = nftnl_expr_alloc("lookup");
	if (!lookup) {
		nftnl_rule_free(r);
		return NULL;
	}
	nftnl_expr_set_u32(lookup, NFTNL_EXPR_LOOKUP_SREG, NFT_REG32_00);
	nftnl_expr_set_str(lookup, NFTNL_EXPR_LOOKUP_SET, pcp_filter_set_name(v4, kind));
	nftnl_expr_set_u32(lookup, NFTNL_EXPR_LOOKUP_SET_ID, pcp_filter_set_id(v4, kind));
	nftnl_rule_add_expr(r, lookup);
	expr_set_reg_verdict(r, kind == PCP_SET_FILTERED ? NF_DROP : NF_ACCEPT);
	if (expr_alloc_failed) {
		nftnl_rule_free(r);
		return NULL;
	}
	return r;
}

/* the messages which create the base chain and the sets of a family (or
 * keep them) and replace its rules. returns <0 if out of memory */
static int
pcp_filter_dispatch_msgs(struct mnl_nlmsg_batch *batch, int *pending, int v4,
                         const char *ifname)
{
	uint16_t family = v4 ? nft_ipv4_family : nft_ipv6_family;
	const char *base = v4 ? PCP_FILTER_BASE4 : PCP_FILTER_BASE6;
	uint32_t alen = pcp_filter_alen(v4);
	uint8_t fields[5];
	struct nftnl_chain *chain = nftnl_chain_alloc();
	struct nftnl_set *sets[PCP_SET_COUNT] = {NULL};
	struct nftnl_rule *flush = nftnl_rule_alloc();
	struct nftnl_rule *rules[PCP_SET_COUNT] = {NULL};
	struct nlmsghdr *nlh;
	int i, result = -1;

	for (i = 0; i < PCP_SET_COUNT; i++) {
		sets[i] = pcp_filter_set(v4, (enum pcp_filter_kind)i);
		rules[i] = pcp_filter_dispatch_rule(v4, (enum pcp_filter_kind)i, ifname);
	}
	if (!chain || !flush)
		goto out;
	for (i = 0; i < PCP_SET_COUNT; i++)
		if (!sets[i] || !rules[i])
			goto out;
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, nft_table);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, base);
	nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, "filter");
	nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, NF_INET_FORWARD);
	nftnl_chain_set_s32(chain, NFTNL_CHAIN_PRIO, -1);
	nlh = nftnl_chain_nlmsg_build_hdr(pcp_filter_batch_msg(batch, pending),
	                                 NFT_MSG_NEWCHAIN, family, NLM_F_CREATE, mnl_seq++);
	nftnl_chain_nlmsg_build_payload(nlh, chain);

	/* the hosts and the filtered mappings : hash sets */
	nftnl_set_set_u32(sets[PCP_SET_PEER], NFTNL_SET_KEY_TYPE, PCP_FILTER_ALLOW_TYPE(v4));
	nftnl_set_set_u32(sets[PCP_SET_PEER], NFTNL_SET_KEY_LEN, 2 * alen + 12);
	nftnl_set_set_u32(sets[PCP_SET_HOST], NFTNL_SET_KEY_TYPE, PCP_FILTER_HOST_TYPE(v4));
	nftnl_set_set_u32(sets[PCP_SET_HOST], NFTNL_SET_KEY_LEN, 2 * alen + 8);
	nftnl_set_set_u32(sets[PCP_SET_FILTERED], NFTNL_SET_KEY_TYPE, PCP_FILTER_FILTERED_TYPE(v4));
	nftnl_set_set_u32(sets[PCP_SET_FILTERED], NFTNL_SET_KEY_LEN, alen + 8);
	/* the prefixes : a set of concatenated ranges */
	fields[0] = (uint8_t)alen; fields[1] = 1; fields[2] = 2;
	fields[3] = (uint8_t)alen; fields[4] = 2;
	nftnl_set_set_u32(sets[PCP_SET_RANGE], NFTNL_SET_FLAGS, NFT_SET_INTERVAL | NFT_SET_CONCAT);
	nftnl_set_set_u32(sets[PCP_SET_RANGE], NFTNL_SET_KEY_TYPE, PCP_FILTER_ALLOW_TYPE(v4));
	nftnl_set_set_u32(sets[PCP_SET_RANGE], NFTNL_SET_KEY_LEN, 2 * alen + 12);
	nftnl_set_set_data(sets[PCP_SET_RANGE], NFTNL_SET_DESC_CONCAT, fields, sizeof(fields));
	for (i = 0; i < PCP_SET_COUNT; i++) {
		nlh = nftnl_set_nlmsg_build_hdr(pcp_filter_batch_msg(batch, pending),
		                               NFT_MSG_NEWSET, family, NLM_F_CREATE, mnl_seq++);
		nftnl_set_nlmsg_build_payload(nlh, sets[i]);
	}

	/* the base chain holds only these rules : flush it, add them */
	nftnl_rule_set_u32(flush, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set_str(flush, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set_str(flush, NFTNL_RULE_CHAIN, base);
	nlh = nftnl_rule_nlmsg_build_hdr(pcp_filter_batch_msg(batch, pending),
	                                NFT_MSG_DELRULE, family, 0, mnl_seq++);
	nftnl_rule_nlmsg_build_payload(nlh, flush);
	for (i = 0; i < PCP_SET_COUNT; i++) {
		nlh = nftnl_rule_nlmsg_build_hdr(pcp_filter_batch_msg(batch, pending),
		                                NFT_MSG_NEWRULE, family,
		                                NLM_F_CREATE | NLM_F_APPEND, mnl_seq++);
		nftnl_rule_nlmsg_build_payload(nlh, rules[i]);
	}
	result = 0;
out:
	for (i = 0; i < PCP_SET_COUNT; i++) {
		if (rules[i])
			nftnl_rule_free(rules[i]);
		if (sets[i])
			nftnl_set_free(sets[i]);
	}
	if (flush)
		nftnl_rule_free(flush);
	if (chain)
		nftnl_chain_free(chain);
	return result;
}

/* add an element to the set of a message (end : the end of a range).
 * returns <0 if out of memory */
static int
pcp_filter_add_elem(struct nftnl_set *set, const unsigned char *key,
                    const unsigned char *end, uint32_t len)
{
	struct nftnl_set_elem *e = nftnl_set_elem_alloc();
	if (!e)
		return -1;
	nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, key, len);
	if (end)
		nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY_END, end, len);
	nftnl_set_elem_add(set, e);	/* the set frees it */
	return 0;
}

/* the message with the elements of a set to add or remove (none : no
 * message) */
static void
pcp_filter_elems_msg(struct mnl_nlmsg_batch *batch, int *pending,
                     struct nftnl_set *set, int n, int add, int v4)
{
	struct nlmsghdr *nlh;
	if (!n)
		return;
	nlh = nftnl_set_elem_nlmsg_build_hdr(pcp_filter_batch_msg(batch, pending),
	                                    add ? NFT_MSG_NEWSETELEM : NFT_MSG_DELSETELEM,
	                                    v4 ? nft_ipv4_family : nft_ipv6_family,
	                                    add ? NLM_F_CREATE : 0, mnl_seq++);
	nftnl_set_elems_nlmsg_build_payload(nlh, set);
}

/* is the peer f, installed in the policy p (NULL : no peer), installed as
 * the same element ? */
static int
pcp_filter_has(const struct pcp_filter_policy *p, const unsigned char *in,
               const struct pcp_filter *f)
{
	unsigned int i;
	if (!p)
		return 0;
	for (i = 0; i < p->count; i++)
		if (in[i] && pcp_filter_equal(&p->filters[i], f))
			return 1;
	return 0;
}

/* Change the elements of a mapping from the policy from (what is in the
 * kernel, NULL or no peer : nothing) to the policy to (no peer : remove
 * everything), in one transaction. Nothing is sent when nothing changes. */
static int
pcp_filter_install(const struct pcp_filter_policy *to,
                   const struct pcp_filter_policy *from)
{
	int v4 = IN6_IS_ADDR_V4MAPPED(&to->address);
	unsigned char in_to[PCP_FILTER_PEER_MAX], in_from[PCP_FILTER_PEER_MAX];
	unsigned char key[PCP_FILTER_KEY_MAX];
	struct nftnl_set *add[PCP_SET_PEER_KINDS] = {NULL}, *del[PCP_SET_PEER_KINDS] = {NULL};
	struct nftnl_set *fset = pcp_filter_set(v4, PCP_SET_FILTERED);
	struct mnl_nlmsg_batch *batch;
	int nadd[PCP_SET_PEER_KINDS] = {0}, ndel[PCP_SET_PEER_KINDS] = {0};
	int k, any = 0;
	unsigned int i, from_count = from ? from->count : 0;
	uint32_t len;
	int pending = 0, result = -1, msgs = 0;
	int dispatch = to->count && (!pcp_filter_dispatch_ready[v4] ||
	               strcmp(pcp_filter_dispatch_ifname[v4], to->ifname) != 0);
	/* an element is less than 200 octets of netlink messages */
	const size_t batch_size = 16384 + (to->count + from_count) * 256;
	char *buf = pcp_filter_bulk ? NULL : malloc(2 * batch_size);	/* libmnl wants twice the limit */

	for (k = 0; k < PCP_SET_PEER_KINDS; k++) {
		add[k] = pcp_filter_set(v4, (enum pcp_filter_kind)k);
		del[k] = pcp_filter_set(v4, (enum pcp_filter_kind)k);
	}
	if (!fset || (!buf && !pcp_filter_bulk))
		goto out;
	for (k = 0; k < PCP_SET_PEER_KINDS; k++)
		if (!add[k] || !del[k])
			goto out;
	memset(in_to, 0, sizeof(in_to));
	memset(in_from, 0, sizeof(in_from));
	pcp_filter_installed(to, in_to);
	if (from)
		pcp_filter_installed(from, in_from);
	for (i = 0; i < from_count; i++) {
		if (!in_from[i] || pcp_filter_has(to, in_to, &from->filters[i]))
			continue;
		k = pcp_filter_peer_kind(&from->filters[i]);
		if (pcp_filter_add_peer(del[k], from, &from->filters[i]) < 0)
			goto out;
		ndel[k]++;
		any = 1;
	}
	for (i = 0; i < to->count; i++) {
		if (!in_to[i] || pcp_filter_has(from, in_from, &to->filters[i]))
			continue;
		k = pcp_filter_peer_kind(&to->filters[i]);
		if (pcp_filter_add_peer(add[k], to, &to->filters[i]) < 0)
			goto out;
		nadd[k]++;
		any = 1;
	}
	if ((to->count != 0) != (from_count != 0)) {
		/* the mapping becomes filtered, or no longer is */
		len = pcp_filter_key_mapping(to, key);
		if (pcp_filter_add_elem(fset, key, NULL, len) < 0)
			goto out;
	}
	if (!dispatch && !any && (to->count != 0) == (from_count != 0)) {
		result = 0;	/* nothing changes in the kernel */
		goto out;
	}
	if (pcp_filter_bulk) {
		batch = pcp_filter_bulk;
		pending = pcp_filter_bulk_pending;
	} else {
		batch = start_batch(buf, batch_size);
	}
	if (!batch)
		goto out;
	if (dispatch && pcp_filter_dispatch_msgs(batch, &pending, v4, to->ifname) < 0)
		goto out;
	/* a mapping which becomes filtered gets its peers first ; one which no
	 * longer is loses its drop first : never a moment without its peers */
	if (!to->count && from_count)
		pcp_filter_elems_msg(batch, &pending, fset, 1, 0, v4);
	for (k = 0; k < PCP_SET_PEER_KINDS; k++)
		pcp_filter_elems_msg(batch, &pending, del[k], ndel[k], 0, v4);
	for (k = 0; k < PCP_SET_PEER_KINDS; k++)
		pcp_filter_elems_msg(batch, &pending, add[k], nadd[k], 1, v4);
	if (to->count && !from_count)
		pcp_filter_elems_msg(batch, &pending, fset, 1, 1, v4);
	msgs = pending;
	if (!msgs) {
		result = 0;
		goto out;
	}
	if (pcp_filter_bulk) {
		/* sent by nft_pcp_filter_bulk_end() */
		pcp_filter_bulk_pending = pending;
		if (dispatch) {
			pcp_filter_dispatch_ready[v4] = 1;
			snprintf(pcp_filter_dispatch_ifname[v4], IFNAMSIZ, "%s", to->ifname);
		}
		result = 0;
		goto out;
	}
	/* One acknowledgement after the complete transaction avoids leaving
	 * multiple ACKs pending on the backend's shared netlink socket. */
	((struct nlmsghdr *)mnl_nlmsg_batch_current(batch))->nlmsg_flags |= NLM_F_ACK;
	result = send_batch(batch);
	if (dispatch) {
		pcp_filter_dispatch_ready[v4] = result >= 0;
		if (result >= 0)
			snprintf(pcp_filter_dispatch_ifname[v4], IFNAMSIZ, "%s", to->ifname);
	}
out:
	for (k = 0; k < PCP_SET_PEER_KINDS; k++) {
		if (add[k])
			nftnl_set_free(add[k]);
		if (del[k])
			nftnl_set_free(del[k]);
	}
	if (fset)
		nftnl_set_free(fset);
	free(buf);
	return result;
}

/* ---- reading the policies back from the kernel after a restart ---- */

struct pcp_filter_recover_ctx {
	int v4;
	enum pcp_filter_kind kind;	/* the set being read */
	int error;	/* out of memory */
};

static void
pcp_filter_free_all(void)
{
	unsigned int b;
	for (b = 0; b < PCP_FILTER_HASH_SIZE; ++b) {
		while (pcp_filter_policies[b]) {
			struct pcp_filter_policy *p = pcp_filter_policies[b];
			pcp_filter_policies[b] = p->next;
			free(p);
		}
	}
}

/* the policy of the mapping at the start of a key, created if need be */
static struct pcp_filter_policy *
pcp_filter_recover_policy(const unsigned char *key, int v4)
{
	uint32_t alen = pcp_filter_alen(v4);
	struct in6_addr address;
	unsigned short port;
	struct pcp_filter_policy **pp;
	memset(&address, 0, sizeof(address));
	if (v4) {
		address.s6_addr[10] = address.s6_addr[11] = 0xff;
		memcpy(address.s6_addr + 12, key, 4);
	} else {
		memcpy(address.s6_addr, key, 16);
	}
	port = (unsigned short)((key[alen + 4] << 8) | key[alen + 5]);
	pp = pcp_filter_find(&address, port, key[alen]);
	if (!*pp) {
		*pp = calloc(1, sizeof(**pp));
		if (*pp) {
			(*pp)->address = address;
			(*pp)->port = port;
			(*pp)->protocol = key[alen];
		}
	}
	return *pp;
}

/* the prefix length of the range low-high, -1 if it is not a prefix */
static int
pcp_filter_range_prefix(const unsigned char *low, const unsigned char *high,
                        uint32_t len)
{
	unsigned int bit, prefix = 0, host = 0;
	for (bit = 0; bit < len * 8; bit++) {
		int l = (low[bit / 8] >> (7 - bit % 8)) & 1;
		int h = (high[bit / 8] >> (7 - bit % 8)) & 1;
		if (!host && l == h) {
			prefix++;
		} else if (l == 0 && h == 1) {
			host = 1;
		} else {
			return -1;
		}
	}
	return (int)prefix;
}

/* an element of a set : a filtered mapping, or a peer of one */
static int
pcp_filter_recover_cb(const struct nlmsghdr *nlh, void *data)
{
	struct pcp_filter_recover_ctx *ctx = data;
	uint32_t alen = pcp_filter_alen(ctx->v4);
	struct nftnl_set *set = nftnl_set_alloc();
	struct nftnl_set_elems_iter *it;
	struct nftnl_set_elem *e;
	if (!set || nftnl_set_elems_nlmsg_parse(nlh, set) < 0) {
		if (set)
			nftnl_set_free(set);
		ctx->error = 1;
		return MNL_CB_OK;
	}
	it = nftnl_set_elems_iter_create(set);
	for (e = it ? nftnl_set_elems_iter_next(it) : NULL; e; e = nftnl_set_elems_iter_next(it)) {
		uint32_t klen = 0, elen = 0;
		const unsigned char *key = nftnl_set_elem_get(e, NFTNL_SET_ELEM_KEY, &klen);
		const unsigned char *end = nftnl_set_elem_get(e, NFTNL_SET_ELEM_KEY_END, &elen);
		struct pcp_filter_policy *p;
		if (!key || klen < alen + 8) {
			ctx->error = 1;
			continue;
		}
		p = pcp_filter_recover_policy(key, ctx->v4);
		if (!p) {
			ctx->error = 1;
			continue;
		}
		if (ctx->kind == PCP_SET_FILTERED) {
			p->seen_filtered = 1;
			continue;
		}
		{
			struct pcp_filter *f;
			int prefix = (int)alen * 8;
			unsigned short plow = 0, phigh = 0xffff;
			if (p->count == PCP_FILTER_PEER_MAX ||
			    klen != 2 * alen + (ctx->kind == PCP_SET_HOST ? 8 : 12)) {
				p->recovery_error |= 1;
				continue;
			}
			if (ctx->kind != PCP_SET_HOST) {
				plow = (unsigned short)((key[2 * alen + 8] << 8) | key[2 * alen + 9]);
				phigh = plow;
			}
			if (ctx->kind == PCP_SET_RANGE) {
				if (!end || elen != klen ||
				    (prefix = pcp_filter_range_prefix(key + alen + 8, end + alen + 8, alen)) < 0) {
					p->recovery_error |= 1;
					continue;
				}
				phigh = (unsigned short)((end[2 * alen + 8] << 8) | end[2 * alen + 9]);
			}
			if (!(plow == phigh || (plow == 0 && phigh == 0xffff))) {
				p->recovery_error |= 1;
				continue;
			}
			f = &p->filters[p->count++];
			memset(f, 0, sizeof(*f));
			if (ctx->v4) {
				f->address.s6_addr[10] = f->address.s6_addr[11] = 0xff;
				memcpy(f->address.s6_addr + 12, key + alen + 8, 4);
				f->prefix = (unsigned char)(prefix + 96);
			} else {
				memcpy(f->address.s6_addr, key + alen + 8, 16);
				f->prefix = (unsigned char)prefix;
			}
			f->port = plow == phigh ? plow : 0;
		}
	}
	if (it)
		nftnl_set_elems_iter_destroy(it);
	nftnl_set_free(set);
	return MNL_CB_OK;
}

/* dump the elements of a set into the policies. returns <0 on error */
static int
pcp_filter_recover_set(int v4, enum pcp_filter_kind kind, struct pcp_filter_recover_ctx *ctx)
{
	uint16_t family = v4 ? nft_ipv4_family : nft_ipv6_family;
	struct nftnl_set *set = pcp_filter_set(v4, kind);
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	ssize_t n;
	int result;
	if (!set)
		return -1;
	ctx->v4 = v4;
	ctx->kind = kind;
	mnl_seq = time(NULL);
	nlh = nftnl_set_elem_nlmsg_build_hdr(buf, NFT_MSG_GETSETELEM, family,
	                                    NLM_F_DUMP, mnl_seq);
	nftnl_set_elems_nlmsg_build_payload(nlh, set);
	nftnl_set_free(set);
	if (mnl_socket_sendto(mnl_sock, nlh, nlh->nlmsg_len) < 0)
		return -1;
	do {
		n = mnl_socket_recvfrom(mnl_sock, buf, sizeof(buf));
		if (n <= 0)
			return -1;
		result = mnl_cb_run(buf, n, mnl_seq, mnl_portid, pcp_filter_recover_cb, ctx);
		if (result < 0)
			return errno == ENOENT ? 0 : -1;	/* ENOENT : no set yet */
	} while (result > 0);
	return 0;
}

/* Kernel state survives a daemon restart : the elements of the sets are
 * read back once, then the policies in memory are authoritative. A mapping
 * whose elements can not be read back (or which has peers but no drop, or
 * a drop but no peer) is kept with recovery_error, so it is never changed
 * blindly. Peers inside an other one were not installed : the PCP lease
 * file gives them back.
 * returns <0 on error (the mapping of address:port/protocol could not be read) */
static int
pcp_filter_recover(const struct in6_addr *address, unsigned short port,
                   unsigned char protocol)
{
	struct pcp_filter_recover_ctx ctx;
	struct pcp_filter_policy *p;
	unsigned int b;
	int v4;
	if (!pcp_filter_recovered) {
		if (!mnl_sock)
			return -1;
		memset(&ctx, 0, sizeof(ctx));
		/* the peers first, then the filtered mappings */
		for (v4 = 1; v4 >= 0; v4--) {
			int k;
			for (k = 0; k < PCP_SET_COUNT; k++) {
				if (pcp_filter_recover_set(v4, (enum pcp_filter_kind)k, &ctx) < 0)
					ctx.error = 1;
			}
			if (ctx.error) {
				syslog(LOG_ERR, "%s: could not read the PCP FILTER sets", "pcp_filter_recover");
				pcp_filter_free_all();
				return -1;	/* tried again next time */
			}
		}
		for (b = 0; b < PCP_FILTER_HASH_SIZE; ++b) {
			for (p = pcp_filter_policies[b]; p; p = p->next) {
				/* peers without the drop, or a drop without peers */
				if ((p->count != 0) != (p->seen_filtered != 0))
					p->recovery_error = 1;
				if (p->recovery_error)
					syslog(LOG_WARNING, "%s: the PCP FILTER elements of port %hu proto %u are inconsistent (%d)",
					       "pcp_filter_recover", p->port, p->protocol, p->recovery_error);
			}
		}
		pcp_filter_recovered = 1;
	}
	p = *pcp_filter_find(address, port, protocol);
	return (p && p->recovery_error) ? -1 : 0;
}

/* Between these two, pcp_filter_install() queues its changes in one transaction
 * of at most size octets : the restore of the PCP lease file sends all the
 * peers at once, before any rule of a mapping exists, instead of a transaction
 * per mapping. The policies are still read from the kernel first, so a mapping
 * which is only there keeps its filter.
 * returns <0 if out of memory or the policies could not be read */
int
nft_pcp_filter_bulk_begin(size_t size)
{
	struct in6_addr any = IN6ADDR_ANY_INIT;
	if (pcp_filter_recover(&any, 0, 0) < 0)
		return -1;
	pcp_filter_bulk_buf = malloc(2 * size);
	if (!pcp_filter_bulk_buf)
		return -1;
	pcp_filter_bulk = start_batch(pcp_filter_bulk_buf, size);
	pcp_filter_bulk_pending = 0;
	if (!pcp_filter_bulk) {
		free(pcp_filter_bulk_buf);
		pcp_filter_bulk_buf = NULL;
		return -1;
	}
	return 0;
}

/* returns <0 if the transaction failed : nothing is in the kernel, the
 * policies are read from it again, and the caller sends them one by one */
int
nft_pcp_filter_bulk_end(void)
{
	struct mnl_nlmsg_batch *batch = pcp_filter_bulk;
	int result = 0;
	if (!batch)
		return 0;
	pcp_filter_bulk = NULL;
	if (pcp_filter_bulk_pending) {
		int size = (int)mnl_nlmsg_batch_size(batch) + MNL_SOCKET_BUFFER_SIZE;
		((struct nlmsghdr *)mnl_nlmsg_batch_current(batch))->nlmsg_flags |= NLM_F_ACK;
		/* larger than the default send buffer. Without the privilege the
		 * send can fail, which is handled as any other failure */
		(void)setsockopt(mnl_socket_get_fd(mnl_sock), SOL_SOCKET, SO_SNDBUFFORCE,
		                 &size, sizeof(size));
		result = send_batch(batch);
	} else {
		mnl_nlmsg_batch_stop(batch);
	}
	free(pcp_filter_bulk_buf);
	pcp_filter_bulk_buf = NULL;
	if (result < 0) {
		syslog(LOG_WARNING, "%s: the bulk load of the PCP FILTER peers failed", "nft_pcp_filter_bulk_end");
		pcp_filter_dispatch_ready[0] = pcp_filter_dispatch_ready[1] = 0;
		pcp_filter_free_all();
		pcp_filter_recovered = 0;
	}
	return result;
}

/* the name of the set which holds a peer, for the PCP lease file */
const char *
nft_pcp_filter_set_label(const struct pcp_filter *f)
{
	switch (pcp_filter_peer_kind(f)) {
	case PCP_SET_PEER:
		return "peer";
	case PCP_SET_HOST:
		return "host";
	default:
		return "range";
	}
}

int
nft_pcp_filter_begin(const struct in6_addr *address, unsigned short port,
                     unsigned char protocol, const char *ifname,
                     const struct pcp_filter *filters, unsigned int count,
                     struct pcp_filter_update **update)
{
	struct pcp_filter_update *u;
	struct pcp_filter_policy *p;
	int v4 = IN6_IS_ADDR_V4MAPPED(address);
	int r;

	*update = NULL;
	if (!ifname || !*ifname || strlen(ifname) >= IFNAMSIZ ||
	    pcp_filter_recover(address, port, protocol) < 0)
		return -1;
	u = calloc(1, sizeof(*u));
	p = calloc(1, sizeof(*p));
	if (!u || !p) {
		free(u);
		free(p);
		return -1;
	}
	u->old = *pcp_filter_find(address, port, protocol);
	u->replacement = p;
	if (u->old)
		*p = *u->old;
	p->next = NULL;
	p->address = *address;
	p->port = port;
	p->protocol = protocol;
	strcpy(p->ifname, ifname);
	r = pcp_filter_merge(p->filters, &p->count, filters, count, v4);
	if (r < 0) {
		free(p);
		free(u);
		return r;
	}
	/* a renewal with the peers the mapping has : the chain stays as it is */
	if (pcp_filter_same(p, u->old)) {
		u->unchanged = 1;
		*update = u;
		return 0;
	}
	if (pcp_filter_install(p, u->old) < 0) {
		free(p);
		free(u);
		return -1;
	}
	*update = u;
	return 0;
}

int
nft_pcp_filter_finish(struct pcp_filter_update *update, int commit)
{
	struct pcp_filter_policy **p;
	int result = 0;
	if (!update)
		return 0;
	if (update->unchanged) {
		/* nothing was installed : the policy in memory stays */
		free(update->replacement);
		free(update);
		return 0;
	}
	p = pcp_filter_find(&update->replacement->address,
	                    update->replacement->port, update->replacement->protocol);
	if (commit && update->replacement->count == 0) {
		/* no peer left (a FILTER with prefix 0) : the chain and the
		 * element are gone, the mapping is unfiltered */
		if (update->old)
			*p = update->old->next;
		free(update->old);
		free(update->replacement);
	} else if (commit) {
		update->replacement->next = update->old ? update->old->next : *p;
		*p = update->replacement;
		free(update->old);
	} else {
		/* the kernel has the replacement : back to the previous peers */
		if (update->old) {
			result = pcp_filter_install(update->old, update->replacement);
		} else {
			struct pcp_filter_policy *none = malloc(sizeof(*none));
			if (none) {
				*none = *update->replacement;
				none->count = 0;
				result = pcp_filter_install(none, update->replacement);
				free(none);
			} else {
				result = -1;
			}
		}
		free(update->replacement);
	}
	free(update);
	return result;
}

/* the FILTER peers of a mapping, IPv4 or IPv6 (for pcp_lease.c) */
unsigned int
nft_pcp_filter_get(const struct in6_addr *address, unsigned short port,
                   unsigned char protocol, struct pcp_filter *filters,
                   unsigned int max)
{
	struct pcp_filter_policy *p;
	unsigned int n;
	if (pcp_filter_recover(address, port, protocol) < 0)
		return 0;
	p = *pcp_filter_find(address, port, protocol);
	if (!p)
		return 0;
	n = p->count < max ? p->count : max;
	memcpy(filters, p->filters, n * sizeof(*filters));
	return n;
}

int
nft_pcp_filter_delete(const struct in6_addr *address, unsigned short port,
                      unsigned char protocol)
{
	struct pcp_filter_policy **p, *old;
	struct pcp_filter_policy empty;
	int result;
	if (delete_batch_active) {
		struct delete_policy *d;
		if (delete_batch_policy_count == NFT_DELETE_BATCH_MAX)
			nft_delete_batch_flush();
		d = &delete_batch_policies[delete_batch_policy_count++];
		d->address = *address;
		d->port = port;
		d->protocol = protocol;
		d->rule_end = delete_batch_count;
		d->rule_failed = delete_batch_group_failed;
		delete_batch_group_failed = 0;
		return 0;
	}
	if (pcp_filter_recover(address, port, protocol) < 0)
		return -1;
	p = pcp_filter_find(address, port, protocol);
	if (!*p)
		return 0;
	old = *p;
	if (!old->count) {
		/* nothing is installed for a policy without peers */
		*p = old->next;
		free(old);
		return 0;
	}
	empty = *old;
	empty.count = 0;
	result = pcp_filter_install(&empty, old);
	if (result >= 0) {
		*p = old->next;
		free(old);
	}
	return result;
}
