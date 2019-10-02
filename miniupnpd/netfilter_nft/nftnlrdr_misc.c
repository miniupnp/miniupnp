/* $Id: nftnlrdr_misc.c,v 1.4 2019/06/30 20:00:41 nanard Exp $ */
/*
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2015 Tomofumi Hayashi
 * (c) 2019 Thomas Bernard
 * (c) 2019 Paul Chambers
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
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/ipv6.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "../commonrdr.h"
#include "nftnlrdr_misc.h"
#include "../macros.h"


#ifdef DEBUG
#define d_printf(x) do { printf x; } while (0)
#else
#define d_printf(x)
#endif

#if defined(DEBUG) && (__STDC_VERSION__ >= 199901L) && (__GNUC__ >= 3)
/* disambiguate log messages by adding position in source. GNU C99 or later. Pesky trailing comma... */
#define log_error( msg, ...)	syslog(LOG_ERR, "%s[%d]: " msg, __func__, __LINE__, ##__VA_ARGS__ )
#define log_debug( msg, ...)	syslog(LOG_DEBUG, "%s[%d]: " msg, __func__, __LINE__, ##__VA_ARGS__ )
#else
/* original style */
#define log_error(args...)	syslog(LOG_ERR, args)
#define log_debug(args...)	syslog(LOG_DEBUG, args)
#endif


#define RULE_CACHE_INVALID  0
#define RULE_CACHE_VALID    1

const char * nft_table = "miniupnpd";
const char * nft_prerouting_chain = "prerouting";
const char * nft_postrouting_chain = "postrouting";
const char * nft_forward_chain = "forward";

static struct mnl_socket *nl = NULL;
static uint32_t nl_seq = 0;

// FILTER
struct rule_list head_filter = LIST_HEAD_INITIALIZER(head_filter);
// DNAT
struct rule_list head_redirect = LIST_HEAD_INITIALIZER(head_redirect);
// SNAT
struct rule_list head_peer = LIST_HEAD_INITIALIZER(head_peer);

static uint32_t rule_list_filter_validate = RULE_CACHE_INVALID;
static uint32_t rule_list_redirect_validate = RULE_CACHE_INVALID;
static uint32_t rule_list_peer_validate = RULE_CACHE_INVALID;

#ifdef DEBUG
static const char *
get_family_string(uint32_t family)
{
	switch (family) {
	case NFPROTO_INET:
		return "ipv4/6";
	case NFPROTO_IPV4:
		return "ipv4";
	case NFPROTO_IPV6:
		return "ipv6";
	}

	return "unknown family";
}

static const char *
get_proto_string(uint32_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	}

	return "unknown proto";
}

static const char *
get_verdict_string(uint32_t val)
{
	switch (val) {
	case NF_ACCEPT:
		return "accept";
	case NF_DROP:
		return "drop";
	default:
		return "unknown verdict";
	}
}

void
print_rule(rule_t *r)
{
	struct in_addr addr;
	char *iaddr_str = NULL, *rhost_str = NULL, *eaddr_str = NULL;
	char iaddr6_str[INET6_ADDRSTRLEN];
	char rhost6_str[INET6_ADDRSTRLEN];
	char ifname_buf[IF_NAMESIZE];

	switch (r->type) {
	case RULE_NAT:
		if (r->iaddr != 0) {
			addr.s_addr = r->iaddr;
			iaddr_str = strdupa(inet_ntoa(addr));
		}
		if (r->rhost != 0) {
			addr.s_addr = r->rhost;
			rhost_str = strdupa(inet_ntoa(addr));
		}
		if (r->eaddr != 0) {
			addr.s_addr = r->eaddr;
			eaddr_str = strdupa(inet_ntoa(addr));
		}
		if (r->nat_type == NFT_NAT_DNAT) {
			printf("%"PRIu64":[%s/%s] iif %s, %s/%s, %d -> "
			       "%s:%d (%s)\n",
			       r->handle,
			       r->table, r->chain,
			       if_indextoname(r->ingress_ifidx, ifname_buf),
			       get_family_string(r->family),
			       get_proto_string(r->proto), r->eport,
			       iaddr_str, r->iport,
			       r->desc);
		} else if (r->nat_type == NFT_NAT_SNAT) {
			printf("%"PRIu64":[%s/%s] "
			       "nat type:%d, family:%d, ifidx: %d, "
			       "eaddr: %s, eport:%d, "
			       "proto:%d, iaddr: %s, "
			       "iport:%d, rhost:%s rport:%d (%s)\n",
			       r->handle, r->table, r->chain,
			       r->nat_type, r->family, r->ingress_ifidx,
			       eaddr_str, r->eport,
			       r->proto, iaddr_str, r->iport,
			       rhost_str, r->rport,
			       r->desc);
		} else {
			printf("%"PRIu64":[%s/%s] "
			       "nat type:%d, family:%d, ifidx: %d, "
			       "eaddr: %s, eport:%d, "
			       "proto:%d, iaddr: %s, iport:%d, rhost:%s (%s)\n",
			       r->handle, r->table, r->chain,
			       r->nat_type, r->family, r->ingress_ifidx,
			       eaddr_str, r->eport,
			       r->proto, iaddr_str, r->iport, rhost_str,
			       r->desc);
		}
		break;
	case RULE_FILTER:
		if (r->iaddr != 0) {
			addr.s_addr = r->iaddr;
			iaddr_str = strdupa(inet_ntoa(addr));
		}
		if (r->rhost != 0) {
			addr.s_addr = r->rhost;
			rhost_str = strdupa(inet_ntoa(addr));
		}
		inet_ntop(AF_INET6, &r->iaddr6, iaddr6_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &r->rhost6, rhost6_str, INET6_ADDRSTRLEN);

		if ( (r->iaddr != 0) || (r->rhost != 0) ) {
			printf("%"PRIu64":[%s/%s] %s/%s, %s %s:%d: %s (%s)\n",
			       r->handle, r->table, r->chain,
			       get_family_string(r->family), get_proto_string(r->proto),
			       rhost_str,
			       iaddr_str, r->eport,
			       get_verdict_string(r->filter_action),
			       r->desc);
		} else {
			printf("%"PRIu64":[%s/%s] %s/%s, %s %s:%d: %s (%s)\n",
			       r->handle, r->table, r->chain,
			       get_family_string(r->family), get_proto_string(r->proto),
			       rhost6_str,
			       iaddr6_str, r->eport,
			       get_verdict_string(r->filter_action),
			       r->desc);
		}
		break;
	case RULE_COUNTER:
		if (r->iaddr != 0) {
			addr.s_addr = r->iaddr;
			iaddr_str = strdupa(inet_ntoa(addr));
		}
		if (r->rhost != 0) {
			addr.s_addr = r->iaddr;
			rhost_str = strdupa(inet_ntoa(addr));
		}
		printf("%"PRIu64":[%s/%s] %s/%s, %s:%d: "
		       "packets:%"PRIu64", bytes:%"PRIu64"\n",
		       r->handle, r->table, r->chain,
		       get_family_string(r->family), get_proto_string(r->proto),
		       iaddr_str, r->eport, r->packets, r->bytes);
		break;
	default:
		printf("nftables: unknown type: %d\n", r->type);
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

static inline void
parse_rule_immediate(struct nftnl_expr *e, rule_t *r)
{
	uint32_t dreg, reg_val, reg_len;

	dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_DREG);

	if (dreg == NFT_REG_VERDICT) {
		reg_val = nftnl_expr_get_u32(e, NFTNL_EXPR_IMM_VERDICT);
	} else {
		reg_val = *(uint32_t *)nftnl_expr_get(e,
							 NFTNL_EXPR_IMM_DATA,
							 &reg_len);
	}

	set_reg(r, dreg, RULE_REG_IMM_VAL, reg_val);
}

static inline void
parse_rule_counter(struct nftnl_expr *e, rule_t *r)
{
	r->type = RULE_COUNTER;
	r->bytes = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_BYTES);
	r->packets = nftnl_expr_get_u64(e, NFTNL_EXPR_CTR_PACKETS);
}

static inline void
parse_rule_meta(struct nftnl_expr *e, rule_t *r)
{
	uint32_t key = nftnl_expr_get_u32(e, NFTNL_EXPR_META_KEY);
	uint32_t dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_META_DREG);
	enum rule_reg_type reg_type;

	/* ToDo: body of both cases are identical - bug? */
	switch (key) {
	case NFT_META_IIF:
		reg_type = RULE_REG_IIF;
		set_reg(r, dreg, reg_type, 0);
		break;
	case NFT_META_OIF:
		reg_type = RULE_REG_IIF;
		set_reg(r, dreg, reg_type, 0);
		break;
	default:
		log_debug("parse_rule_meta :Not support key %d\n", key);
		break;
	}
}

static inline void
parse_rule_nat(struct nftnl_expr *e, rule_t *r)
{
	uint32_t addr_min_reg, addr_max_reg, proto_min_reg, proto_max_reg;
	uint16_t proto_min_val;
	r->type = RULE_NAT;

	r->nat_type = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_TYPE);
	r->family = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_FAMILY);
	addr_min_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MIN);
	addr_max_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_ADDR_MAX);
	proto_min_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MIN);
	proto_max_reg = nftnl_expr_get_u32(e, NFTNL_EXPR_NAT_REG_PROTO_MAX);

	if (addr_min_reg != addr_max_reg ||
	    proto_min_reg != proto_max_reg) {
		log_error( "Unsupport proto/addr range for NAT");
	}

	proto_min_val = htons((uint16_t)*get_reg_val_ptr(r, proto_min_reg));
	if (r->nat_type == NFT_NAT_DNAT) {
		r->iaddr = (in_addr_t)*get_reg_val_ptr(r, addr_min_reg);
		r->iport = proto_min_val;
	} else if (r->nat_type == NFT_NAT_SNAT) {
		r->eaddr = (in_addr_t)*get_reg_val_ptr(r, addr_min_reg);
		if (proto_min_reg == NFT_REG_1) {
			r->eport = proto_min_val;
		}
	}

	set_reg(r, NFT_REG_1, RULE_REG_NONE, 0);
	set_reg(r, NFT_REG_2, RULE_REG_NONE, 0);
}

static inline void
parse_rule_payload(struct nftnl_expr *e, rule_t *r)
{
	uint32_t  base, dreg, offset, len;
	uint32_t  *regptr;

	dreg = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_DREG);
	base = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_BASE);
	offset = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET);
	len = nftnl_expr_get_u32(e, NFTNL_EXPR_PAYLOAD_LEN);
	regptr = get_reg_type_ptr(r, dreg);

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
		}
		break;
	case NFT_PAYLOAD_TRANSPORT_HEADER:
		if (offset == offsetof(struct tcphdr, dest) &&
		    len == sizeof(uint16_t)) {
			*regptr = RULE_REG_TCP_DPORT;
		} else if (offset == offsetof(struct tcphdr, source) &&
			   len == sizeof(uint16_t) * 2) {
			*regptr = RULE_REG_TCP_SD_PORT;
		}
		break;
	default:
		syslog(LOG_DEBUG,
			   "Unsupported payload: (dreg:%d, base:%d, offset:%d, len:%d)",
			   dreg, base, offset, len);
		break;
	}

}

/*
 *
 * Note: Currently support only NFT_REG_1
 */
static inline void
parse_rule_cmp(struct nftnl_expr *e, rule_t *r) {
	uint32_t data_len;
	void *data_val;
	uint32_t op, sreg;
	uint16_t *ports;
	in_addr_t *addrp;
	struct in6_addr *addrp6;

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

	data_val = (void *)nftnl_expr_get(e, NFTNL_EXPR_CMP_DATA, &data_len);

	switch (r->reg1_type) {
	case RULE_REG_IIF:
		if (data_len == sizeof(uint32_t)) {
			r->ingress_ifidx = *(uint32_t *)data_val;
		}
		break;
	case RULE_REG_IP_SRC_ADDR:
		if (data_len == sizeof(in_addr_t)) {
			r->rhost = *(in_addr_t *)data_val;
		}
		break;
	case RULE_REG_IP6_SRC_ADDR:
		if (data_len == sizeof(struct in6_addr)) {
			r->rhost6 = *(struct in6_addr *)data_val;
		}
		break;
	case RULE_REG_IP_DEST_ADDR:
		if (data_len == sizeof(in_addr_t)) {
			if (r->type == RULE_FILTER) {
				r->iaddr = *(in_addr_t *)data_val;
			} else {
				r->rhost = *(in_addr_t *)data_val;
			}
		}
		break;
	case RULE_REG_IP6_DEST_ADDR:
		if (data_len == sizeof(struct in6_addr)) {
			if (r->type == RULE_FILTER) {
				r->iaddr6 = *(struct in6_addr *)data_val;
			} else {
				r->rhost6 = *(struct in6_addr *)data_val;
			}
		}
		break;
	case RULE_REG_IP_SD_ADDR:
		if (data_len == sizeof(in_addr_t) * 2) {
			addrp = (in_addr_t *)data_val;
			r->iaddr = addrp[0];
			r->rhost = addrp[1];
		}
		break;
	case RULE_REG_IP6_SD_ADDR:
		if (data_len == sizeof(struct in6_addr) * 2) {
			addrp6 = (struct in6_addr *)data_val;
			r->iaddr6 = addrp6[0];
			r->rhost6 = addrp6[1];
		}
		break;
	case RULE_REG_IP_PROTO:
	case RULE_REG_IP6_PROTO:
		if (data_len == sizeof(uint8_t)) {
			r->proto = *(uint8_t *)data_val;
		}
		break;
	case RULE_REG_TCP_DPORT:
		if (data_len == sizeof(uint16_t)) {
			r->eport = ntohs(*(uint16_t *)data_val);
		}
		break;
	case RULE_REG_TCP_SD_PORT:
		if (data_len == sizeof(uint16_t) * 2) {
			ports = (uint16_t *)data_val;
			r->eport = ntohs(ports[0]);
			r->rport = ntohs(ports[1]);
		}
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
rule_expr_cb(struct nftnl_expr *e, void *data)
{
	rule_t *r = data;
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


static int
table_cb(const struct nlmsghdr *nlh, void *data)
{
	int result = MNL_CB_OK;
	struct nftnl_rule *t;
	uint32_t len;
	struct nftnl_expr *expr;
	struct nftnl_expr_iter *itr;
	rule_t *r;
	char *chain;
	char *descr;
	int index_filter, index_peer, index_redirect;
	UNUSED(data);

	index_filter = index_peer = index_redirect = 0;

	r = malloc(sizeof(rule_t));

	if (r == NULL) {
		log_error("out of memory: %m");
	} else {
		memset(r, 0, sizeof(rule_t));
		t = nftnl_rule_alloc();
		if (t == NULL) {
			log_error("nftnl_rule_alloc() FAILED");
		} else {

			if (nftnl_rule_nlmsg_parse(nlh, t) < 0) {
				log_error("nftnl_rule_nlmsg_parse FAILED");
			} else {

				chain = (char *) nftnl_rule_get_data(t, NFTNL_RULE_CHAIN, &len);
				if (strcmp(chain, nft_prerouting_chain) == 0 ||
					strcmp(chain, nft_postrouting_chain) == 0 ||
					strcmp(chain, nft_forward_chain) == 0) {
					r->table = strdup(
							(char *) nftnl_rule_get_data(t, NFTNL_RULE_TABLE, &len));
					r->chain = strdup(chain);
					r->family = *(uint32_t *) nftnl_rule_get_data(t, NFTNL_RULE_FAMILY,
																  &len);
					descr = (char *) nftnl_rule_get_data(t, NFTNL_RULE_USERDATA,
														 &r->desc_len);
					if (r->desc_len > 0)
						r->desc = strndup(descr, r->desc_len);

					r->handle = *(uint32_t *) nftnl_rule_get_data(t,
																  NFTNL_RULE_HANDLE,
																  &len);
					r->type = RULE_NONE;
					if (strcmp(chain, nft_prerouting_chain) == 0 ||
						strcmp(chain, nft_postrouting_chain) == 0) {
						r->type = RULE_NAT;
					} else if (strcmp(chain, nft_forward_chain) == 0) {
						r->type = RULE_FILTER;
					}

					itr = nftnl_expr_iter_create(t);

					while ((expr = nftnl_expr_iter_next(itr)) != NULL) {
						rule_expr_cb(expr, r);
					}

					switch (r->type) {
					case RULE_NAT:
						switch (r->nat_type) {
						case NFT_NAT_SNAT:
							r->index = index_peer;
							LIST_INSERT_HEAD(&head_peer, r, entry);
							index_peer++;
							break;
						case NFT_NAT_DNAT:
							r->index = index_redirect;
							LIST_INSERT_HEAD(&head_redirect, r, entry);
							index_redirect++;
							break;
						}
						break;

					case RULE_FILTER:
						r->index = index_filter;
						LIST_INSERT_HEAD(&head_filter, r, entry);
						index_filter++;
						break;

					default:
						free(r);
						break;
					}
				}

				nftnl_rule_free(t);
			}
		}
	}
	return result;
}

void
refresh_nft_cache_filter(void) {
	if (rule_list_filter_validate != RULE_CACHE_VALID) {
		refresh_nft_cache(&head_filter, nft_table, nft_forward_chain, NFPROTO_INET);
		rule_list_filter_validate = RULE_CACHE_VALID;
	}
}

void
refresh_nft_cache_peer(void) {
	if (rule_list_peer_validate != RULE_CACHE_VALID) {
		refresh_nft_cache(&head_peer, nft_table, nft_postrouting_chain, NFPROTO_IPV4);
		rule_list_peer_validate = RULE_CACHE_VALID;
	}
}

void
refresh_nft_cache_redirect(void)
{
	if (rule_list_redirect_validate != RULE_CACHE_VALID) {
		refresh_nft_cache(&head_redirect, nft_table, nft_prerouting_chain, NFPROTO_IPV4);
		rule_list_redirect_validate = RULE_CACHE_VALID;
	}
}

void
flush_nft_cache(struct rule_list *head)
{
	rule_t *p1, *p2;

	p1 = LIST_FIRST(head);
	if (p1 != NULL) {
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
	}
	LIST_INIT(head);
}

void
refresh_nft_cache(struct rule_list *head, const char *table, const char *chain, uint32_t family)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t portid, seq, type = NFTNL_OUTPUT_DEFAULT;
	struct nftnl_rule *t;
	int ret;

	flush_nft_cache(head);

	if (nl == NULL) {
		nl = mnl_socket_open(NETLINK_NETFILTER);
		if (nl == NULL) {
			log_error("mnl_socket_open() FAILED: %m");
			return;
		}

		if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
			log_error("mnl_socket_bind() FAILED: %m");
			return;
		}
	}
	portid = mnl_socket_get_portid(nl);

	t = nftnl_rule_alloc();
	if (t == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return;
	}

	seq = time(NULL);
	nlh = nftnl_rule_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, family,
					NLM_F_DUMP, seq);
	nftnl_rule_set(t, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(t, NFTNL_RULE_CHAIN, chain);
	nftnl_rule_nlmsg_build_payload(nlh, t);
	nftnl_rule_free(t);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		log_error("mnl_socket_sendto() FAILED: %m");
		return;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	while (ret > 0) {
		ret = mnl_cb_run(buf, ret, seq, portid, table_cb, &type);
		if (ret <= 0)
			break;
		ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	}

	if (ret == -1) {
		log_error("mnl_socket_recvfrom() FAILED: %m");
	}

	/* mnl_socket_close(nl); */

	return;
}

static void
expr_add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
                 uint32_t offset, uint32_t len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("payload");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "payload");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

	nftnl_rule_add_expr(r, e);
}

#if 0
static void
expr_add_bitwise(struct nftnl_rule *r, uint32_t sreg, uint32_t dreg,
		 uint32_t len, uint32_t mask, uint32_t xor)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("bitwise");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "expr_add_bitwise()", "bitwise");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_LEN, len);
	nftnl_expr_set(e, NFTNL_EXPR_BITWISE_MASK, &mask, sizeof(mask));
	nftnl_expr_set(e, NFTNL_EXPR_BITWISE_XOR, &xor, sizeof(xor));

	nftnl_rule_add_expr(r, e);
}
#endif

static void
expr_add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
	     const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "cmp");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

static void
expr_add_meta(struct nftnl_rule *r, uint32_t meta_key, uint32_t dreg)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("meta");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED", "meta");
		return;
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, meta_key);
	nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);

	nftnl_rule_add_expr(r, e);
}

static void
expr_set_reg_val_u32(struct nftnl_rule *r, enum nft_registers dreg, uint32_t val)
{
	struct nftnl_expr *e;
	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "immediate");
		return;
	}
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DATA, val);
	nftnl_rule_add_expr(r, e);
}

static void
expr_set_reg_val_u16(struct nftnl_rule *r, enum nft_registers dreg, uint32_t val)
{
	struct nftnl_expr *e;
	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "immediate");
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
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "immediate");
		return;
	}
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, val);
	nftnl_rule_add_expr(r, e);
}

static void
expr_add_nat(struct nftnl_rule *r, uint32_t t, uint32_t family,
	     in_addr_t addr_min, uint32_t proto_min, uint32_t flags)
{
	struct nftnl_expr *e;
	UNUSED(flags);

	e = nftnl_expr_alloc("nat");
	if (e == NULL) {
		log_error("nftnl_expr_alloc(\"%s\") FAILED",   "nat");
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
	#ifdef DEBUG
	char buf[8192];
	#endif
	UNUSED(handle);

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, nft_postrouting_chain);

	if (descr != NULL && *descr != '\0') {
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, strlen(descr));
	}

	/* Destination IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, daddr), sizeof(uint32_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &ihost, sizeof(uint32_t));

	/* Source IP */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, saddr), sizeof(in_addr_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &rhost, sizeof(in_addr_t));

	/* Protocol */
	expr_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
	                 offsetof(struct iphdr, protocol), sizeof(uint8_t));
	expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));

	/* Source and Destination Port of Protocol */
	if (proto == IPPROTO_TCP) {
		/* Destination Port */
		dport = htons(iport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

		/* Source Port */
		sport = htons(rport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct tcphdr, source), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
	} else if (proto == IPPROTO_UDP) {
		/* Destination Port */
		dport = htons(iport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, dest), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));

		/* Source Port */
		sport = htons(rport);
		expr_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1,
		                 offsetof(struct udphdr, source), sizeof(uint16_t));
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
	}

	expr_add_nat(r, NFT_NAT_SNAT, family, ehost, htons(eport), 0);

	#ifdef DEBUG
	nftnl_rule_snprintf(buf, sizeof(buf), r, NFTNL_OUTPUT_DEFAULT, 0);
	fprintf(stdout, "%s\n", buf);
	#endif

	return r;
}

struct nftnl_rule *
rule_set_dnat(uint8_t family, const char * ifname, uint8_t proto,
	      in_addr_t rhost, unsigned short eport,
	      in_addr_t ihost, uint32_t iport,
	      const char *descr,
	      const char *handle)
{
	struct nftnl_rule *r = NULL;
	uint16_t dport;
	uint64_t handle_num;
	uint32_t if_idx;
	#ifdef DEBUG
	char buf[8192];
	#endif

	UNUSED(handle);

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, nft_prerouting_chain);

	if (descr != NULL && *descr != '\0') {
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, strlen(descr));
	}

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	if (ifname != NULL) {
		if_idx = (uint32_t)if_nametoindex(ifname);
		expr_add_meta(r, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &if_idx,
			     sizeof(uint32_t));
	}

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

	expr_add_nat(r, NFT_NAT_DNAT, family, ihost, htons(iport), 0);

	#ifdef DEBUG
	nftnl_rule_snprintf(buf, sizeof(buf), r, NFTNL_OUTPUT_DEFAULT, 0);
	fprintf(stdout, "%s\n", buf);
	#endif

	return r;
}

struct nftnl_rule *
rule_set_filter(uint8_t family, const char * ifname, uint8_t proto,
		in_addr_t rhost, in_addr_t iaddr,
		unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	struct nftnl_rule *r = NULL;
	#ifdef DEBUG
	char buf[8192];
	#endif
	UNUSED(eport);

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	r = rule_set_filter_common(r, family, ifname, proto, eport, iport, rport, descr, handle);

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

	#ifdef DEBUG
	nftnl_rule_snprintf(buf, sizeof(buf), r, NFTNL_OUTPUT_DEFAULT, 0);
	fprintf(stdout, "%s\n", buf);
	#endif

	return r;
}

struct nftnl_rule *
rule_set_filter6(uint8_t family, const char * ifname, uint8_t proto,
		struct in6_addr *rhost6, struct in6_addr *iaddr6,
		unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	struct nftnl_rule *r = NULL;
	#ifdef DEBUG
	char buf[8192];
	#endif
	UNUSED(eport);

	r = nftnl_rule_alloc();
	if (r == NULL) {
		log_error("nftnl_rule_alloc() FAILED");
		return NULL;
	}

	r = rule_set_filter_common(r, family, ifname, proto, eport, iport, rport, descr, handle);

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

	#ifdef DEBUG
	nftnl_rule_snprintf(buf, sizeof(buf), r, NFTNL_OUTPUT_DEFAULT, 0);
	fprintf(stdout, "%s\n", buf);
	#endif

	return r;
}

struct nftnl_rule *
rule_set_filter_common(struct nftnl_rule *r, uint8_t family, const char * ifname,
		uint8_t proto, unsigned short eport, unsigned short iport,
		unsigned short rport, const char *descr, const char *handle)
{
	uint16_t dport, sport;
	uint64_t handle_num;
	uint32_t if_idx;
	UNUSED(eport);

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, nft_table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, nft_forward_chain);

	if (descr != NULL && *descr != '\0') {
		nftnl_rule_set_data(r, NFTNL_RULE_USERDATA,
							descr, strlen(descr));
	}

	if (handle != NULL) {
		handle_num = atoll(handle);
		nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, handle_num);
	}

	if (ifname != NULL) {
		if_idx = (uint32_t)if_nametoindex(ifname);
		expr_add_meta(r, NFT_META_IIF, NFT_REG_1);
		expr_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &if_idx,
			     sizeof(uint32_t));
	}

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

	nftnl_rule_set(r, NFTNL_RULE_TABLE, rule->table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, rule->chain);
	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, rule->family);
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

int
nft_send_rule(struct nftnl_rule * rule, uint16_t cmd, enum rule_chain_type chain_type)
{
    int result = -1;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE];


	batch = start_batch(buf, sizeof(buf));
	if (batch != NULL)
    {
        switch (chain_type) {
        case RULE_CHAIN_FILTER:
            rule_list_filter_validate = RULE_CACHE_INVALID;
            break;
        case RULE_CHAIN_PEER:
            rule_list_peer_validate = RULE_CACHE_INVALID;
            break;
        case RULE_CHAIN_REDIRECT:
            rule_list_redirect_validate = RULE_CACHE_INVALID;
            break;
        }
        nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                         cmd,
                                         nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY),
                                         NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK,
                                         nl_seq++);

        nftnl_rule_nlmsg_build_payload(nlh, rule);
        nftnl_rule_free(rule);

        result = send_batch(batch);
    }

	return result;
}

int
table_op( enum nf_tables_msg_types op, uint16_t family, const char * name)
{
    int result;
    struct nlmsghdr *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    struct nftnl_table *table;

	// log_debug("(%d, %d, %s)", op, family, name);

    table = nftnl_table_alloc();
    if (table == NULL) {
        log_error("out of memory: %m");
        result = -1;
    } else {
        nftnl_table_set_u32(table, NFTNL_TABLE_FAMILY, family);
        nftnl_table_set_str(table, NFTNL_TABLE_NAME, name);

        batch = start_batch( buf, sizeof(buf));
        if (batch == NULL) {
            log_error("out of memory: %m");
            result = -2;
        } else {
            nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                              op, family,
                                              (op == NFT_MSG_NEWTABLE ? NLM_F_CREATE : 0) | NLM_F_ACK,
                                              nl_seq++);
            nftnl_table_nlmsg_build_payload(nlh, table);

            result = send_batch(batch);
        }
        nftnl_table_free(table);
    }
    return result;
}

int
chain_op(enum nf_tables_msg_types op, uint16_t family, const char * table,
		 const char * name, const char * type, uint32_t hooknum, signed int priority )
{
    int result = -1;
    struct nlmsghdr *nlh;
    struct mnl_nlmsg_batch *batch;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    struct nftnl_chain *chain;

    // log_debug("(%d, %d, %s, %s, %s, %d, %d)", op, family, table, name, type, hooknum, priority);

    chain = nftnl_chain_alloc();
    if (chain == NULL) {
        log_error("out of memory: %m");
        result = -2;
    } else {
		nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
		nftnl_chain_set(chain, NFTNL_CHAIN_TABLE, table);
		nftnl_chain_set(chain, NFTNL_CHAIN_NAME, name);
		if (op == NFT_MSG_NEWCHAIN) {
			nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, type);
			nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, hooknum);
			nftnl_chain_set_s32(chain, NFTNL_CHAIN_PRIO, priority);
		}

        batch = start_batch( buf, sizeof(buf));
        if (batch == NULL) {
			log_error("out of memory: %m");
            result = -3;
        } else {
            nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                              op, family,
                                              (op == NFT_MSG_NEWCHAIN ? NLM_F_CREATE : 0) | NLM_F_ACK,
                                              nl_seq++);
            if (nlh == NULL)
			{
				log_error("failed to build header: %m");
				result = -4;
			} else {
				nftnl_chain_nlmsg_build_payload(nlh, chain);

				result = send_batch(batch);
            }
        }
        nftnl_chain_free(chain);
    }
    return result;
}


struct mnl_nlmsg_batch *
start_batch( char *buf, size_t buf_size)
{
    struct mnl_nlmsg_batch *batch;
    nl_seq = time(NULL);

    if (nl == NULL) {
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
            log_error("mnl_socket_open() FAILED: %m");
            return NULL;
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
            log_error("mnl_socket_bind() FAILED: %m");
            return NULL;
        }
    }

    batch = mnl_nlmsg_batch_start(buf, buf_size);
    if (batch != NULL) {
        nft_mnl_batch_put(mnl_nlmsg_batch_current(batch),
                          NFNL_MSG_BATCH_BEGIN, nl_seq++);
        mnl_nlmsg_batch_next(batch);
    }
    return batch;
}

int
send_batch(struct mnl_nlmsg_batch * batch)
{
    int ret;
    char buf[MNL_SOCKET_BUFFER_SIZE];

    mnl_nlmsg_batch_next(batch);

    nft_mnl_batch_put(mnl_nlmsg_batch_current(batch), NFNL_MSG_BATCH_END,
                      nl_seq++);
    mnl_nlmsg_batch_next(batch);

    if (nl == NULL) {
        log_error("netlink not connected");
        return -1;
    } else {
        ret = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                                mnl_nlmsg_batch_size(batch));
        if (ret == -1) {
            log_error("mnl_socket_sendto() FAILED: %m");
            return -2;
        }

        mnl_nlmsg_batch_stop(batch);

		do {
			ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
			if (ret == -1) {
				log_error("mnl_socket_recvfrom() FAILED: %m");
				return -3;
			} else if (ret > 0) {
				ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl), NULL, NULL);
				if (ret == -1) {
					log_error("mnl_cb_run() FAILED: %m");
					return -4;
				}
			}
		} while (ret > 0);
    }
    /* mnl_socket_close(nl); */
    return 0;
}

void
finish_batch(void)
{
    mnl_socket_close(nl);
    nl = NULL;
}