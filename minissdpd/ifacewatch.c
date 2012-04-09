/* $Id: ifacewatch.c,v 1.4 2012/04/09 21:50:18 nanard Exp $ */
/* MiniUPnP project
 * (c) 2011 Thomas Bernard
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include "config.h"

#include <stdlib.h>
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
		syslog(LOG_DEBUG, "nlmsg_type=%d", nlhdr->nlmsg_type);
		if(nlhdr->nlmsg_type == NLMSG_DONE)
			break;
		if(nlhdr->nlmsg_type == RTM_NEWADDR) {
			ifa = (struct ifaddrmsg *)NLMSG_DATA(nlhdr);
			syslog(LOG_DEBUG, "ProcessInterfaceWatchNotify RTM_NEWADDR index=%d", ifa->ifa_index);
			for(i = 0; i < n_if_addr; i++) {
				if(ifa->ifa_index == if_nametoindex(if_addr[i])) {
					AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 0);
					break;
				}
			}
		} else if(nlhdr->nlmsg_type == RTM_DELADDR) {
			ifa = (struct ifaddrmsg *)NLMSG_DATA(nlhdr);
			syslog(LOG_DEBUG, "ProcessInterfaceWatchNotify RTM_DELADDR index=%d", ifa->ifa_index);
			for(i = 0; i < n_if_addr; i++) {
				if(ifa->ifa_index == if_nametoindex(if_addr[i])) {
					AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 1);
					break;
				}
			}
		}
	}
#else /* __linux__ */
	struct rt_msghdr * rtm;
	struct ifa_msghdr * ifam;

	len = recv(s, buffer, sizeof(buffer), 0);
	if(len < 0) {
		syslog(LOG_ERR, "ProcessInterfaceWatchNotify recv: %m");
		return -1;
	}
	rtm = (struct rt_msghdr *)buffer;
	switch(rtm->rtm_type) {
	case RTM_NEWADDR:
		ifam = (struct ifa_msghdr *)buffer;
		syslog(LOG_DEBUG, "ProcessInterfaceWatchNotify RTM_NEWADDR index=%d", ifam->ifam_index);
		for(i = 0; i < n_if_addr; i++) {
			if(ifam->ifam_index == if_nametoindex(if_addr[i])) {
				AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 0);
				break;
			}
		}
		break;
	case RTM_DELADDR:
		ifam = (struct ifa_msghdr *)buffer;
		syslog(LOG_DEBUG, "ProcessInterfaceWatchNotify RTM_DELADDR index=%d", ifam->ifam_index);
		for(i = 0; i < n_if_addr; i++) {
			if(ifam->ifam_index == if_nametoindex(if_addr[i])) {
				/* I dont think it is useful */
				/*AddDropMulticastMembership(s_ssdp, if_addr[i], 0, 1);*/
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

