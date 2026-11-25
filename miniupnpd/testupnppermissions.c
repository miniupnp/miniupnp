/* $Id: testupnppermissions.c,v 1.5 2025/04/21 22:56:49 nanard Exp $ */
/* (c) 2007-2025 Thomas Bernard
 * MiniUPnP Project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 */
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "miniupnpdtypes.h"
#include "upnppermissions.h"
#include "mapreq.h"

struct lan_addr_list lan_addrs;
time_t startup_time = 0;

void
print_upnpperm(const struct upnpperm * p)
{
	switch(p->type)
	{
	case UPNPPERM_ALLOW:
		printf("allow ");
		break;
	case UPNPPERM_DENY:
		printf("deny ");
		break;
	default:
		printf("error ! ");
	}
	printf("%hu-%hu ", p->eport_min, p->eport_max);
	printf("%s/", inet_ntoa(p->address));
	printf("%s ", inet_ntoa(p->mask));
	printf("%hu-%hu", p->iport_min, p->iport_max);
	putchar('\n');
}

/* One check of check_upnp_rule_against_permissions(): the IPv4 mapping of
 * 192.168.1.10:iport to eport with label, against rules. 0 if it gives
 * want. */
static int
check_req(const struct upnpperm * rules, int n, unsigned short eport,
          unsigned short iport, const char * label, int want)
{
	struct lease_entry r;
	struct in_addr a;
	int got;

	lease_entry_init(&r, MAP_KIND_UPNP, NULL);
	r.family = AF_INET;
	inet_pton(AF_INET, "192.168.1.10", &a);
	map_addr_v4(&r.iaddr, &a);
	r.iport = iport;
	r.eport = eport;
	r.label = label;
	got = check_upnp_rule_against_permissions(rules, n, &r);
	if(got == want)
		return 0;
	printf("check %hu->%hu label %s: got %d, want %d\n", eport, iport,
	       label ? label : "(none)", got, want);
	return 1;
}

/* The rules applied to a mapping: its ports and internal address, and the
 * regex to its label only. Without a label, a rule with a regex matches on
 * the rest. */
static int
check_requests(void)
{
	static const char * lines[] = {
#ifdef ENABLE_REGEX
		"deny 46000-46100 0.0.0.0/0 46000-46100 \"^bad\"",
#endif
		"allow 46000-46100 192.168.1.0/24 46000-46100",
		"deny 0-65535 0.0.0.0/0 0-65535",
	};
	struct upnpperm rules[3];
	int n = (int)(sizeof(lines) / sizeof(lines[0]));
	int i, fails = 0;

	memset(rules, 0, sizeof(rules));
	for(i = 0; i < n; i++) {
		if(read_permission_line(&rules[i], lines[i]) < 0) {
			printf("cannot read \"%s\"\n", lines[i]);
			return 1;
		}
	}
	fails += check_req(rules, n, 46001, 46001, "good", 1);
	fails += check_req(rules, n, 47001, 46001, "good", 0);
	fails += check_req(rules, n, 46001, 47001, "good", 0);
#ifdef ENABLE_REGEX
	fails += check_req(rules, n, 46001, 46001, "bad one", 0);
	/* no label (NAT-PMP, PCP, UPnP without a description): the deny
	 * rule with a regex matches on its ports and address */
	fails += check_req(rules, n, 46001, 46001, NULL, 0);
#else
	fails += check_req(rules, n, 46001, 46001, NULL, 1);
#endif
	for(i = 0; i < n; i++)
		free_permission_line(&rules[i]);
	printf(fails ? "requests FAILED\n" : "requests OK\n");
	return fails;
}

int main(int argc, char * * argv)
{
	int i, r, ret;
	struct upnpperm p;
	if(argc == 2 && strcmp(argv[1], "--requests") == 0) {
		openlog("testupnppermissions", LOG_PERROR, LOG_USER);
		return check_requests() ? 1 : 0;
	}
	if(argc < 2) {
		fprintf(stderr, "Usage:   %s \"permission line\" [...]\n", argv[0]);
		fprintf(stderr, "Example: %s \"allow 1234 10.10.10.10/32 1234\"\n", argv[0]);
		return 1;
	}
	openlog("testupnppermissions", LOG_PERROR, LOG_USER);
	ret = 0;
	for(i=1; i<argc; i++) {
		printf("%2d '%s'\n", i, argv[i]);
		memset(&p, 0, sizeof(struct upnpperm));
		r = read_permission_line(&p, argv[i]);
		if(r==0) {
			printf("Permission read successfully\n");
			print_upnpperm(&p);
		} else {
			printf("Permission read failed, please check its correctness\n");
			ret++;
		}
		putchar('\n');
	}
	return ret;
}

