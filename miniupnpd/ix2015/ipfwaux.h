/* $Id: ipfwaux.h,v 1.3 2011/02/20 23:43:41 nanard Exp $ */
/*
 * MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2009 Jardel Weyrich
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution
 */
#ifndef __IPFWAUX_H__
#define __IPFWAUX_H__

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
// #include <netinet/ip_fw.h>

/* dummy definitions to make upnp proxy daemon resemble ip_fw code */
#define UPNP_PROXY_CURRENT_API_VERSION 12345 
#define FW_IFNLEN 128

// #define UPNP_PROXY_ADD       1000
// #define UPNP_PROXY_DEL       1001
// #define UPNP_PROXY_GET       1002

// from include/netinet/in.h
// /* Type to represent a port.  */
// typedef uint16_t in_port_t;

  // in.h
  // /* Structure describing an Internet socket address.  */
  // struct sockaddr_in
  // {
  //     __SOCKADDR_COMMON (sin_);
  //     in_port_t sin_port;			/* Port number.  */
  //     struct in_addr sin_addr;		/* Internet address.  */
  // 
  //    /* Pad to size of `struct sockaddr'.  */
  //    unsigned char sin_zero[sizeof (struct sockaddr) -
  //			   __SOCKADDR_COMMON_SIZE -
  //			   sizeof (in_port_t) -
  // sizeof (struct in_addr)];
  //   };

/* Internet address.  */
// typedef uint32_t in_addr_t;
// struct in_addr
//   {
//    in_addr_t s_addr;
//   };


typedef struct ip_fw {
  int version;

  struct {
    struct {
      char name[IFNAMSIZ];
    } fu_via_if;
  } fw_in_if;

  int fw_prot;
  struct sockaddr_in fw_fwd_ip;
  struct in_addr fw_src;
  int fw_pcnt;
  int fw_bcnt;

  struct {
    int fw_pts[2];		/* 0 - external port number? */
  } fw_uar;
} STRUCT_UPNP_PROXY_DUMMY;


// #define UPNP_PROXY_BASE	(UPNP_PROXY_ADD - 5)
// #define UPNP_PROXY_INIT	(UPNP_PROXY_BASE + 1)
// #define UPNP_PROXY_TERM	(UPNP_PROXY_BASE + 2)

// UPNP_PROXY_INIT does something to sock. 
// UPNP_PROXY_TERM closes sock
// UPNP_PROXY_SET  set or get socket option
// UPNP_PROXY_GET 
#if 0
static int upnp_proxy_exec(int optname, void * optval, uintptr_t optlen);
#endif

static void upnp_proxy_free_ruleset(struct ip_fw ** rules) {
	if (rules == NULL || *rules == NULL)
		return;
	free(*rules);
	*rules = NULL;
}

#if 0
/* we do not need this for ix2015 */
static int upnp_proxy_fetch_ruleset(struct ip_fw ** rules, int * total_fetched, int count) 
#endif

static int upnp_proxy_validate_protocol(int value) {

	switch (value) {
		case IPPROTO_TCP:
		  fprintf(stderr, "upnp_proxy_validate_protocol: TCP\n");
		  break;
		case IPPROTO_UDP:
		  fprintf(stderr, "upnp_proxy_validate_protocol: UDP\n");
		  break;
		default:
		  fprintf(stderr, "upnp_proxy_validate_protocol: invalid protocol=%d\n", value);
		  syslog(LOG_ERR, "invalid protocol");
		  return -1;
	}
	return 0;
}

static int upnp_proxy_validate_ifname(const char * const value) {
	int len = strlen(value);
	printf("upnp_proxy_validate_ifname: <<%s>>\n", value);
	if (len < 2 || len > FW_IFNLEN) {
		syslog(LOG_ERR, "invalid interface name");
		return -1;
	}
	return 0;
}

#endif
