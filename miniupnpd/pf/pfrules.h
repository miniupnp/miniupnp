/* MiniUPnP project
 * Shared helpers to walk the rules of the miniupnpd pf anchor.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#ifndef PFRULES_H_INCLUDED
#define PFRULES_H_INCLUDED

/* the label of a rule : an array of labels with libpfctl and recent pf,
 * a single string with older versions */
#ifdef USE_LIBPFCTL
#define PF_RULE_LABEL_OF(r)	((r).label[0])
#else
#define PF_RULE_LABEL_OF(r)	((r).label)
#endif

#ifdef USE_LIBPFCTL
typedef struct pfctl_rule pf_walk_rule_t;
#else
typedef struct pf_rule pf_walk_rule_t;
#endif

/* state of a walk, for the callbacks which need to read more of the
 * kernel state (pool addresses with the ioctl interface) */
struct pf_walk {
	int action;		/* PF_PASS, PF_RDR, PF_NAT, ... */
	unsigned int ticket;
};

/* called for each rule, index is the position in the ruleset.
 * return 0 to continue, non zero to stop the walk. */
typedef int (*pf_rule_cb)(int index, const pf_walk_rule_t * rule,
                          const struct pf_walk * walk, void * ctx);

/* call cb for each rule of the miniupnpd anchor having this action.
 * returns 1 if the walk was stopped by cb, 0 if it reached the end of the
 * rules, -1 on error */
int pf_rule_foreach(int action, pf_rule_cb cb, void * ctx);

/* call cb for the rule at this index of the miniupnpd anchor.
 * returns -1 if the rule could not be read (or the index is out of range),
 * else the value returned by cb */
int pf_rule_get(int action, int index, pf_rule_cb cb, void * ctx);

/* remove the rule at this index of the miniupnpd anchor ruleset selected by
 * action (PF_PASS, PF_RDR, PF_NAT, ...).
 * returns 0 on success, -1 on error */
int pf_rule_remove(int action, int index);

#endif
