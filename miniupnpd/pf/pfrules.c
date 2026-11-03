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

int
pf_rule_foreach(int action, pf_rule_cb cb, void * ctx)
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
	for(i=0; i<n; i++) {
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
		return -1;
	}
	return 0;
}

#endif /* USE_PF */
