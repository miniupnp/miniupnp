/* $Id: ifacewatch.c,v 1.7 2012/05/15 22:02:23 nanard Exp $ */
/* MiniUPnP project
 * (c) 2011-2012 Thomas Bernard
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else	/* __linux__ */
#include <net/route.h>
#endif
#include <syslog.h>

#include "openssdpsocket.h"

int
OpenAndConfInterfaceWatchSocket(void)
{
	int s;
#ifdef __linux__
	struct sockaddr_nl addr;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
#else	/* __linux__*/
	/*s = socket(PF_ROUTE, SOCK_RAW, AF_INET);*/
	s = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
/* The family parameter may be AF_UNSPEC which will provide routing informa-
 * tion for all address families, or can be restricted to a specific address
 * family by specifying which one is desired.  There can be more than one
 * routing socket open per system. */
#endif
	if(s < 0) {
		syslog(LOG_ERR, "OpenAndConfInterfaceWatchSocket socket: %m");
		return -1;
	}
#ifdef __linux__
	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "bind(netlink): %m");
		close(s);
		return -1;
	}
#endif
	return s;
}

/**
 * Process the message and add/drop multicast membership if needed
 */
int
ProcessInterfaceWatch(int s, int s_ssdp, int s_ssdp6,
                      int n_if_addr, const char * * if_addr)
{
	ssize_t len;
	int i;
	char buffer[4096];
#ifdef __linux__
	struct iovec iov;
	struct msghdr hdr;
	struct nlmsghdr *nlhdr;
	struct ifaddrmsg *ifa;
	struct rtattr *rta;
	int ifa_len;

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	len = recvmsg(s, &hdr, 0);
	if(len < 0) {
		syslog(LOG_ERR, "recvmsg(s, &hdr, 0): %m");
		return -1;
	}

	for(nlhdr = (struct nlmsghdr *)buffer;
		NLMSG_OK(nlhdr, len);
		nlhdr = NLMSG_NEXT(nlhdr, len)) {
		int is_del = 0;
		char address[48];
		char ifname[IFNAMSIZ];
		address[0] = '\0';
		ifname[0] = '\0';
		if(nlhdr->nlmsg_type == NLMSG_DONE)
			break;
		switch(nlhdr->nlmsg_type) {
		/* case RTM_NEWLINK: */
		/* case RTM_DELLINK: */
		case RTM_DELADDR:
			is_del = 1;
		case RTM_NEWADDR:
			/* http://linux-hacks.blogspot.fr/2009/01/sample-code-to-learn-netlink.html */
			ifa = (struct ifaddrmsg *)NLMSG_DATA(nlhdr);
			rta = (struct rtattr *)IFA_RTA(ifa);
			ifa_len = IFA_PAYLOAD(nlhdr);
			syslog(LOG_DEBUG, "%s %s index=%d fam=%d prefixlen=%d flags=%d scope=%d",
			       "ProcessInterfaceWatchNotify", is_del ? "RTM_DELADDR" : "RTM_NEWADDR",
			       ifa->ifa_index, ifa->ifa_family, ifa->ifa_prefixlen,
			       ifa->ifa_flags, ifa->ifa_scope);
			for(;RTA_OK(rta, ifa_len); rta = RTA_NEXT(rta, ifa_len)) {
				/*RTA_DATA(rta)*/
				/*rta_type : IFA_ADDRESS, IFA_LOCAL, etc. */
				char tmp[128];
				memset(tmp, 0, sizeof(tmp));
				switch(rta->rta_type) {
				case IFA_ADDRESS:
				case IFA_LOCAL:
				case IFA_BROADCAST:
				case IFA_ANYCAST:
					inet_ntop(ifa->ifa_family, RTA_DATA(rta), tmp, sizeof(tmp));
					if(rta->rta_type == IFA_ADDRESS)
						strncpy(address, tmp, sizeof(address));
					break;
				case IFA_LABEL:
					strncpy(tmp, RTA_DATA(rta), sizeof(tmp));
					strncpy(ifname, tmp, sizeof(ifname));
					break;
				case IFA_CACHEINFO:
					{
						struct ifa_cacheinfo *cache_info;
						cache_info = RTA_DATA(rta);
						snprintf(tmp, sizeof(tmp), "valid=%u prefered=%u",
						         cache_info->ifa_valid, cache_info->ifa_prefered);
					}
					break;
				default:
					strncpy(tmp, "*unknown*", sizeof(tmp));
				}
				syslog(LOG_DEBUG, " rta_len=%d rta_type=%d '%s'", rta->rta_len, rta->rta_type, tmp);
			}
			for(i = 0; i < n_if_addr; i++) {
				if((0 == strcmp(address, if_addr[i])) ||
				   (0 == strcmp(ifname, if_addr[i])) ||
				   (ifa->ifa_index == if_nametoindex(if_addr[i]))) {
					if(ifa->ifa_family == AF_INET && address[0] != '\0')
						AddDropMulticastMembership(s_ssdp, address, 0, is_del);
					else if(ifa->ifa_family == AF_INET6)
						AddDropMulticastMembership(s_ssdp6, if_addr[i], 1, is_del);
					break;
				}
			}
			break;
		default:
			syslog(LOG_DEBUG, "unknown nlmsg_type=%d", nlhdr->nlmsg_type);
		}
	}
#else /* __linux__ */
	struct rt_msghdr * rtm;
	struct ifa_msghdr * ifam;

	len = recv(s, buffer, sizeof(buffer), 0);
	if(len < 0) {
		syslog(LOG_ERR, "%s recv: %m", "ProcessInterfaceWatchNotify");
		return -1;
	}
	rtm = (struct rt_msghdr *)buffer;
	switch(rtm->rtm_type) {
	case RTM_NEWADDR:
		ifam = (struct ifa_msghdr *)buffer;
		syslog(LOG_DEBUG, "%s %s index=%d",
		       "ProcessInterfaceWatchNotify", "RTM_NEWADDR", ifam->ifam_index);
		for(i = 0; i < n_if_addr; i++) {
			if(ifam->ifam_index == if_nametoindex(if_addr[i])) {
				AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 0);
				AddDropMulticastMembership(s_ssdp6, if_addr[i], 1, 0);
				break;
			}
		}
		break;
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)buffer;
		syslog(LOG_DEBUG, "%s %s index=%d",
		       "ProcessInterfaceWatchNotify", "RTM_DELADDR", ifam->ifam_index);
		for(i = 0; i < n_if_addr; i++) {
			if(ifam->ifam_index == if_nametoindex(if_addr[i])) {
				/* I dont think it is useful */
				/*AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 1);*/
				/*AddDropMulticastMembership(s_ssdp6, if_addr[i], 1, 1);*/
				break;
			}
		}
		break;
	default:
		syslog(LOG_DEBUG, "Unknown RTM message : rtm->rtm_type=%d", rtm->rtm_type);
	}
#endif
	return 0;
}

