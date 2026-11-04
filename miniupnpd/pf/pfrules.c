/* MiniUPnP project
 * Shared helpers to walk the rules of the miniupnpd pf anchor.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#ifdef __DragonFly__
#include <net/pf/pfvar.h>
#else
#ifdef __APPLE__
#define PRIVATE 1
#endif
#include <net/pfvar.h>
#endif
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#ifdef USE_LIBPFCTL
#include <libpfctl.h>
#endif

#include "../macros.h"
#include "../upnpglobalvars.h"
#include "rtickets.h"
#include "pfrules.h"

#ifdef USE_PF

/* /dev/pf when opened */
extern int dev;

/* A copy of the rules of the anchor, per action. Reading a rule is an ioctl, and
 * a request walks the rules, so without it a request costs N ioctls. All the
 * rules of the anchor are added at the tail, and pf_rule_remove() keeps the copy
 * up to date, so a walk only has to read what is new. The number of rules, the
 * ticket and the last rule tell if something else changed the anchor : then all
 * is read again. The counters in the copy are not fresh, see
 * pf_rule_cache_invalidate(). */
#define PF_CACHE_ACTIONS 4
struct pf_rule_cache {
	int used;
	int action;
	int n, size;
	pf_walk_rule_t * rules;
	in_addr_t * pool_addrs;
	struct pf_walk walk;
};
static struct pf_rule_cache pf_cache[PF_CACHE_ACTIONS];
static int pf_walk_n;			/* of the last walk : the number of rules */
static unsigned int pf_walk_ticket;	/* and the ticket */

void
pf_rule_cache_invalidate(void)
{
	int i;
	for(i = 0; i < PF_CACHE_ACTIONS; i++)
	{
		pf_cache[i].used = 0;
		pf_cache[i].n = 0;
	}
}

static struct pf_rule_cache *
pf_cache_of(int action)
{
	int i;
	for(i = 0; i < PF_CACHE_ACTIONS; i++)
	{
		if(pf_cache[i].action == action || pf_cache[i].rules == NULL)
		{
			pf_cache[i].action = action;
			return &pf_cache[i];
		}
	}
	return NULL;
}

static int
pf_cache_add_cb(int index, const pf_walk_rule_t * rule,
                const struct pf_walk * walk, void * ctx)
{
	struct pf_rule_cache * s = ctx;
	(void)index;
	if(s->n == s->size)
	{
		int size = s->size ? s->size * 2 : 256;
		pf_walk_rule_t * r = realloc(s->rules, size * sizeof(*r));
		in_addr_t * a;
		if(r == NULL)
			return 1;	/* the copy is incomplete */
		s->rules = r;
		a = realloc(s->pool_addrs, size * sizeof(*a));
		if(a == NULL)
			return 1;
		s->pool_addrs = a;
		s->size = size;
	}
	s->pool_addrs[s->n] = 0;
	s->rules[s->n++] = *rule;
	s->walk = *walk;
	return 0;
}

static int
pf_cache_same_cb(int index, const pf_walk_rule_t * rule,
                 const struct pf_walk * walk, void * ctx)
{
	const struct pf_rule_cache * s = ctx;
	(void)walk;
	return memcmp(&PF_RULE_LABEL_OF(s->rules[index]), &PF_RULE_LABEL_OF(*rule),
	              sizeof(PF_RULE_LABEL_OF(*rule))) == 0;
}

static int pf_rule_walk(int action, int start, pf_rule_cb cb, void * ctx);

int
pf_rule_foreach(int action, pf_rule_cb cb, void * ctx)
{
	struct pf_rule_cache * s;
	int i;
#ifdef PF_RELEASETICKETS
	/* a callback can read more with the ticket of the walk */
	return pf_rule_walk(action, 0, cb, ctx);
#endif
	s = pf_cache_of(action);
	if(s == NULL)
		return pf_rule_walk(action, 0, cb, ctx);
	/* only the number of rules and the ticket */
	if(pf_rule_walk(action, INT_MAX, NULL, NULL) < 0)
		return -1;
	if(s->used && (pf_walk_n < s->n ||
	   (s->n > 0 && pf_rule_get(action, s->n - 1, pf_cache_same_cb, s) != 1)))
		s->used = 0;
	if(!s->used)
		s->n = 0;
	if(!s->used || pf_walk_n != s->n)
	{
		if(pf_rule_walk(action, s->n, pf_cache_add_cb, s) != 0)
		{
			s->used = 0;
			s->n = 0;
			return pf_rule_walk(action, 0, cb, ctx);
		}
		s->used = 1;
	}
	s->walk.action = action;
	s->walk.ticket = pf_walk_ticket;
	for(i = 0; i < s->n; i++)
	{
		s->walk.pool_addr = &s->pool_addrs[i];
		if(cb(i, &s->rules[i], &s->walk, ctx))
			return 1;
	}
	return 0;
}

/* the walk over the rules from index start */
static int
pf_rule_walk(int action, int start, pf_rule_cb cb, void * ctx)
{
	int i, n, r = 0;
	struct pf_walk walk;
	unsigned int tnum = 0;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
	char anchor_call[MAXPATHLEN] = "";
#else
	struct pfioc_rule pr;
#endif
	if(dev<0)
		return -1;
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, action, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
	walk.ticket = ri.ticket;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif
#else
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	pr.rule.action = action;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
	walk.ticket = pr.ticket;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif
	walk.action = action;
	walk.pool_addr = NULL;
	pf_walk_n = n;
	pf_walk_ticket = walk.ticket;
	for(i=start; i<n; i++) {
#ifdef USE_LIBPFCTL
		if(pfctl_get_rule(dev, i, ri.ticket, anchor_name, action, &rule, anchor_call) < 0)
		{
			syslog(LOG_ERR, "pfctl_get_rule: %m");
			r = -1;
			break;
		}
		if(cb(i, &rule, &walk, ctx))
#else
		pr.nr = i;
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE, ...): %m");
			r = -1;
			break;
		}
		if(cb(i, &pr.rule, &walk, ctx))
#endif
		{
			r = 1;
			break;
		}
	}
	release_ticket(dev, tnum);
	return r;
}

int
pf_rule_get(int action, int index, pf_rule_cb cb, void * ctx)
{
	int n, r = -1;
	struct pf_walk walk;
	unsigned int tnum = 0;
#ifdef USE_LIBPFCTL
	struct pfctl_rules_info ri;
	struct pfctl_rule rule;
	char anchor_call[MAXPATHLEN] = "";
#else
	struct pfioc_rule pr;
#endif
	if(index < 0 || dev<0)
		return -1;
#ifdef USE_LIBPFCTL
	if(pfctl_get_rules_info(dev, &ri, action, anchor_name) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rules_info: %m");
		return -1;
	}
	n = ri.nr;
	walk.ticket = ri.ticket;
#ifdef PF_RELEASETICKETS
	tnum = ri.ticket;
#endif
#else
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	pr.rule.action = action;
#endif
	if(ioctl(dev, DIOCGETRULES, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULES, ...): %m");
		return -1;
	}
	n = pr.nr;
	walk.ticket = pr.ticket;
#ifdef PF_RELEASETICKETS
	tnum = pr.ticket;
#endif
#endif
	walk.action = action;
	walk.pool_addr = NULL;
	if(index >= n)
		goto end;
#ifdef USE_LIBPFCTL
	if(pfctl_get_rule(dev, index, ri.ticket, anchor_name, action, &rule, anchor_call) < 0)
	{
		syslog(LOG_ERR, "pfctl_get_rule: %m");
		goto end;
	}
	r = cb(index, &rule, &walk, ctx);
#else
#if defined(OpenBSD) && OpenBSD >= 202310
	/* OpenBSD >= 7.4
	 * DIOCGETRULE is changed to always get rules incrementaly
	 * pr.nr is now a return value
	 * https://github.com/openbsd/src/commit/072583c99019a91ac511a1e33e10ad02df79ec97 */
	do {
		if(ioctl(dev, DIOCGETRULE, &pr) < 0)
		{
			syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
			goto end;
		}
	} while(pr.nr < (unsigned int)index);
#else
	/* not OpenBSD >= 7.4 */
	pr.nr = index;
	if(ioctl(dev, DIOCGETRULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCGETRULE): %m");
		goto end;
	}
#endif /* defined(OpenBSD) && OpenBSD >= 202310 */
	r = cb(index, &pr.rule, &walk, ctx);
#endif
end:
	release_ticket(dev, tnum);
	return r;
}

int
pf_rule_remove(int action, int index)
{
	struct pfioc_rule pr;
	if(dev<0)
		return -1;
	/* TODO: convert DIOCCHANGERULE to libpfctl */
	memset(&pr, 0, sizeof(pr));
	strlcpy(pr.anchor, anchor_name, MAXPATHLEN);
#ifndef PF_NEWSTYLE
	pr.rule.action = action;	/* selects the ruleset for the DIOCCHANGERULE calls */
#else
	UNUSED(action);
#endif
	pr.action = PF_CHANGE_GET_TICKET;
	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_GET_TICKET: %m");
		return -1;
	}
	pr.action = PF_CHANGE_REMOVE;
	pr.nr = index;
	if(ioctl(dev, DIOCCHANGERULE, &pr) < 0)
	{
		syslog(LOG_ERR, "ioctl(dev, DIOCCHANGERULE, ...) PF_CHANGE_REMOVE: %m");
		pf_rule_cache_invalidate();
		return -1;
	}
	{
		struct pf_rule_cache * s = pf_cache_of(action);
		if(s != NULL && s->used)
		{
			if(index < s->n)
			{
				memmove(&s->rules[index], &s->rules[index + 1],
				        (s->n - index - 1) * sizeof(s->rules[0]));
				memmove(&s->pool_addrs[index], &s->pool_addrs[index + 1],
				        (s->n - index - 1) * sizeof(s->pool_addrs[0]));
				s->n--;
			}
			else
				s->used = 0;
		}
	}
	return 0;
}

#endif /* USE_PF */
