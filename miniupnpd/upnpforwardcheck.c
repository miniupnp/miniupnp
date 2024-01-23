/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2021 Pali Rohár
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#ifndef TEST_LINUX_DEBUG_APP
#include "config.h"
#endif

#include "upnputils.h"
#include "getifaddr.h"
#include "upnpforwardcheck.h"

#if defined(USE_NETFILTER)
#include "netfilter/iptcrdr.h"
#endif
#if defined(USE_PF)
#include "pf/obsdrdr.h"
#endif
#if defined(USE_IPF)
#include "ipf/ipfrdr.h"
#endif
#if defined(USE_IPFW)
#include "ipfw/ipfwrdr.h"
#endif

#ifdef TEST_LINUX_DEBUG_APP
static int add_filter_rule2(const char *ifname, const char *rhost, const char *iaddr, unsigned short eport, unsigned short iport, int proto, const char *desc);
static int delete_filter_rule(const char * ifname, unsigned short port, int proto);
#define syslog(priority, format, ...) do { switch(priority) { case LOG_ERR: printf("Error: "); break; case LOG_WARNING: printf("Warning: "); } printf(format, ##__VA_ARGS__); putchar('\n'); } while (0)
#endif

/* Create two UDP sockets (one for sending, one for receiving) and return file descriptors and receiving port */
static int create_sockets(const char *if_name, struct in_addr *send_addr, struct in_addr *receive_addr, int *send_fd, int *receive_fd, unsigned short *receive_port)
{
	socklen_t sockaddr_len;
	struct sockaddr_in sockaddr;

	*receive_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*receive_fd < 0) {
		syslog(LOG_ERR, "%s: socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP): %m",
		       "create_sockets");
		return -1;
	}

#ifdef SO_BINDTODEVICE
	if (setsockopt(*receive_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) != 0) {
		syslog(LOG_ERR, "%s: setsockopt(SOL_SOCKET, SO_BINDTODEVICE, %s): %m",
		       "create_sockets", if_name);
		return -1;
	}
#endif

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr = *receive_addr;
	sockaddr.sin_port = htons(0);

	if (bind(*receive_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
		syslog(LOG_ERR, "%s: bind(): %m",
		       "create_sockets");
		close(*receive_fd);
		return -1;
	}

	sockaddr_len = sizeof(sockaddr);
	if (getsockname(*receive_fd, (struct sockaddr *)&sockaddr, &sockaddr_len) != 0) {
		syslog(LOG_ERR, "%s: getsockname(): %m",
		       "create_sockets");
		close(*receive_fd);
		return -1;
	}

	*receive_port = ntohs(sockaddr.sin_port);

	*send_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (*send_fd < 0) {
		syslog(LOG_ERR, "%s: socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP): %m",
		       "create_sockets");
		return -1;
		close(*receive_fd);
	}

#ifdef SO_BINDTODEVICE
	if (setsockopt(*send_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) != 0) {
		syslog(LOG_ERR, "%s: setsockopt(SOL_SOCKET, SO_BINDTODEVICE, %s): %m",
		       "create_sockets", if_name);
		close(*receive_fd);
		close(*send_fd);
		return -1;
	}
#endif

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr = *send_addr;
	sockaddr.sin_port = htons(*receive_port);

	if (connect(*send_fd, (struct sockaddr *)&sockaddr, sockaddr_len) != 0) {
		syslog(LOG_ERR, "%s: connect(): %m",
		       "create_sockets");
		return -1;
		close(*receive_fd);
		close(*send_fd);
	}

	return 0;
}

/* Wait for UDP response messages and check it */
static int check_response(int fd, unsigned char expected_char)
{
	fd_set fdset;
	struct timeval timeout;
	int ret;
	unsigned char recv_char;

	timeout.tv_sec = 0;
	timeout.tv_usec = 250*1000;

	while (timeout.tv_sec > 0 || timeout.tv_usec > 0) {

		FD_ZERO(&fdset);
		FD_SET(fd, &fdset);

		syslog(LOG_DEBUG, "%s: waiting %ld secs and %ld usecs", "check_response", (long)timeout.tv_sec, (long)timeout.tv_usec);
		ret = select(fd+1, &fdset, NULL, NULL, &timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "%s: select(): %m", "check_response");
			return -1;
		}
		if (ret == 0 || !FD_ISSET(fd, &fdset)) {
			syslog(LOG_DEBUG, "%s: select(): no response", "check_response");
			return 0;
		}

		ret = recv(fd, &recv_char, 1, 0);
		if (ret < 0) {
			syslog(LOG_ERR, "%s: recv(): %m", "check_response");
			return 0;
		} else if (ret != 1 || recv_char != expected_char) {
			syslog(LOG_ERR, "%s: recv(): invalid response", "check_response");
			return 0;
		}

		syslog(LOG_DEBUG, "%s: received response", "check_response");
		return 1;

	}

	syslog(LOG_DEBUG, "%s: no response", "check_response");
	return 0;
}

int perform_forwarding_check(const char *if_name, const char *if_addr_str, struct in_addr *if_addr, struct in_addr *ext_addr)
{
	int send_fd, receive_fd;
	unsigned short receive_port;
	unsigned char send_char;
	int success;
	int i;

	if (create_sockets(if_name, ext_addr, if_addr, &send_fd, &receive_fd, &receive_port) != 0)
		return -1;

	syslog(LOG_INFO, "%s: receive port %hu",
	       "perform_forwarding_check", receive_port);

	/* Unblock local receive port */
	if (add_filter_rule2(if_name, NULL, if_addr_str, receive_port, receive_port, IPPROTO_UDP, "forwarding check") < 0) {
		syslog(LOG_ERR, "%s: add_filter_rule2(..., %hu, ...) FAILED",
		       "perform_forwarding_check", receive_port);
	}

	send_char = random();
	success = 0;

	/* Send UDP packet to receive port for target address and wait for responce */
	for (i = 0; i < 10; i++) {
		syslog(LOG_DEBUG, "%s: sendto(): sending check byte", "perform_forwarding_check");
		if (send(send_fd, &send_char, 1, 0) != 1) {
			syslog(LOG_ERR, "%s: sendto(): %m", "perform_forwarding_check");
			break;
		}
		if (check_response(receive_fd, send_char)) {
			success = 1;
			break;
		}
	}

	/* Remove unblock for local receive port */
	delete_filter_rule(if_name, receive_port, IPPROTO_UDP);

	if (!success)
		return 1;

	return 0;
}

#ifdef TEST_LINUX_DEBUG_APP

/* This linux test application for debugging purposes can be compiled as: */
/* gcc upnpforwardcheck.c getifaddr.o upnputils.o -o upnpforwardcheck -g3 -W -Wall -O2 -DTEST_LINUX_DEBUG_APP */

#include <arpa/inet.h>
#include <time.h>

#include "upnpglobalvars.h"
struct lan_addr_list lan_addrs;
int runtime_flags = 0;
time_t startup_time = 0;

static int add_filter_rule2(const char *ifname, const char *rhost, const char *iaddr, unsigned short eport, unsigned short iport, int proto, const char *desc)
{
	char buffer[100];
	ifname = ifname;
	rhost = rhost;
	iaddr = iaddr;
	iport = iport;
	desc = desc;
	snprintf(buffer, sizeof(buffer), "/sbin/iptables -t filter -I INPUT -p %d --dport %hu -j ACCEPT", proto, eport);
	printf("Executing: %s\n", buffer);
	return system(buffer);
}

static int delete_filter_rule(const char * ifname, unsigned short port, int proto)
{
	char buffer[100];
	ifname = ifname;
	snprintf(buffer, sizeof(buffer), "/sbin/iptables -t filter -D INPUT -p %d --dport %hu -j ACCEPT", proto, port);
	printf("Executing: %s\n", buffer);
	return system(buffer);
}

int main(int argc, char *argv[])
{
	const char *if_name, *if_addr_str, *ext_addr_str;
	struct in_addr if_addr, ext_addr;
	char buf[INET_ADDRSTRLEN];
	int ret;

	if (argc < 2 || argc > 4) {
		printf("Usage: %s if_name [if_addr [ext_addr] ]\n", argv[0]);
		return 1;
	}

	if_name = argv[1];
	if (!if_name[0] || strlen(if_name) >= IFNAMSIZ) {
		printf("Invalid if_name %s\n", if_name);
		return 1;
	}

	if (argc > 2) {
		if_addr_str = argv[2];
		if (inet_pton(AF_INET, if_addr_str, &if_addr) != 1) {
			printf("Invalid if_addr %s\n", if_addr_str);
			return 1;
		}
	} else {
		if (getifaddr(if_name, buf, sizeof(buf), &if_addr, NULL) < 0) {
			printf("Cannot obtain IP address for interface %s\n", if_name);
			return 1;
		}
		if_addr_str = buf;
	}

	if (argc > 3) {
		ext_addr_str = argv[3];
		if (inet_pton(AF_INET, ext_addr_str, &ext_addr) != 1) {
			printf("Invalid ext_addr %s\n", ext_addr_str);
			return 1;
		}
	} else {
		ext_addr = if_addr;
		ext_addr_str = if_addr_str;
	}

	if (addr_is_reserved(&ext_addr)) {
		printf("External IP address %s is invalid\n", ext_addr_str);
		return 1;
	}

	if (geteuid() != 0) {
		printf("You need to run this application as root\n");
		return 1;
	}

	srandom(time(NULL) * getpid());

	printf("Testing port forwarding on interface %s ", if_name);
	if (strcmp(if_addr_str, ext_addr_str) == 0)
		printf("for public IP address %s", ext_addr_str);
	else
		printf("from public external IP address %s to private local IP address %s", ext_addr_str, if_addr_str);
	printf("...\n");

	ret = perform_forwarding_check(if_name, if_addr_str, &if_addr, &ext_addr);
	if (ret < 0)
		return 1;

	if (ret == 0) {
		printf("Forwarding check passed, port forwarding should work\n");
	} else if (strcmp(if_addr_str, ext_addr_str) == 0) {
		printf("Forwarding check failed, firewall on local machine is blocking port forwarding\n");
	} else {
		printf("Forwarding check failed, firewall on upstream router %s is blocking port forwarding\n", ext_addr_str);
	}

	return 0;
}

#endif
