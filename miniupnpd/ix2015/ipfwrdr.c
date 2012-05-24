/* $Id: ipfwrdr.c,v 1.12 2012/02/11 13:10:57 nanard Exp $ */
/*
 * MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2009 Jardel Weyrich
 * (c) 2011-2012 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution

 * IX2015 version mods.

 */

#include "../config.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>

/*
This is a workaround for <sys/uio.h> troubles on FreeBSD, HPUX, OpenBSD.
Needed here because on some systems <sys/uio.h> gets included by things
like <sys/socket.h>
*/
#ifndef _KERNEL
#  define ADD_KERNEL
#  define _KERNEL
#  define KERNEL
#endif
#ifdef __OpenBSD__
struct file;
#endif
#include <sys/uio.h>
#ifdef ADD_KERNEL
#  undef _KERNEL
#  undef KERNEL
#endif

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>
#if __FreeBSD_version >= 300000
#  include <net/if_var.h>
#endif
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <stddef.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
// #include <netinet/ip_fw.h>
#include "ipfwaux.h"
#include "ipfwrdr.h"

#include "../upnpglobalvars.h"

/* mkdir(2) */
#include <sys/stat.h>
#include <sys/types.h>

/* for strlcpy */
#if defined(__linux__) 
#include <bsd/string.h>
#endif

/* WEXITSTATUS for solaris */
#if defined(__sun)
#include <sys/wait.h>
#endif

/* ======================================== */
int verbose = 1; 		/* incremented in ../miniupnpd.c  */

/* dumy */
int WANIPConnection_Set_PortMappingNumberOfEntries(char *cp) {   return 0; }

/* dumy */
int WANIPConnection_Set_Uptime(char *cp) { return 0; }

/* to store the external IP address string. */
static char __UpnpProxy_external_address[128];

int WANIPConnection_Set_ExternalIPAddress(char *cp) 
{ 
  strncpy(__UpnpProxy_external_address, cp, 128);
  return 0; 
}

char *
UpnpProxy_external_address(void)
{
  return __UpnpProxy_external_address;
}

/* ======================================== */
#include "../getifstats.h"

/* dummy routine to return reasonably looking values.*/
int
getifstats(const char * ifname, struct ifdata * data)
{
  syslog(LOG_ERR, "getifstats: ifname = <<%s>>\n", ifname);

  if (data == NULL)
    return -1;

  data->baudrate = 4200000;	/* that is the answer */
  data->opackets = 1;		
  data->ipackets = 1;
  data->obytes = 128;		/* if zero, maybe we will be in trouble */
  data->ibytes = 256;		/* because miniupnpd may release the mapping. */
  return 0;
}

/* ======================================== */

#define LOCKDIR "/tmp/upnp-daemon-lock-dir"

#include "./ix2015-func.c"

int   load_router_info_failed = 0;




/* ======================================== */




/* init and shutdown functions */

int init_redirect(void) {
  /* initialize : what do we do ? 
     TODO: maybe reading the external map file for getting the correct idea
     of what rules the router has now, and
     initialize in-core / in-memory data structure accordingly.
     Maybe also creating the lock directory.
     But note that now we use upnpd's idea of locking.
   */

  // todo create lock directory and other initialization chore.

  /* create lock directory 
   */
  {
    if(mkdir(LOCKDIR, 0x744) != 0)
      {
	perror(LOCKDIR);
	syslog(LOG_ERR, "LOCKDIR: %s could not be created. Aborting ...\n", LOCKDIR);
	exit(1);
      }
  }

  if ( IGD_NAT_rule_load() < 0)
    {
      load_router_info_failed = 1;
      UpnpProxy_SampleUtil_Print 
	("Loading router data by logging into it failed. "
	 "Quitting.\nCheck the power/cable, etc.\n");	  
      shutdown_redirect(); 	/* layer violation, but I need to remove the lock dir. */
      return -1;
    }

  return 0; /*upnp_proxy_exec(UPNP_PROXY_INIT, NULL, 0);  ipfw socket を開く？ */

}

void shutdown_redirect(void) {
  /* shutdown: what do we need to do?
     TODO: maybe nothing?
     Except for deleting the lock directory, maybe!
     now we use upnpd's idea of locking.
   */

  // dump nat file
  if(!load_router_info_failed)
    IGD_NAT_rule_dump();		
  else
    UpnpProxy_SampleUtil_Print("NAT table dump skipped since the initial load failed.\n");


  // todo remove locking directory


  /*
   * remove locking directory.
   */
  {
    if(rmdir(LOCKDIR) != 0)
      {
	perror(LOCKDIR);
	syslog(LOG_ERR, "LOCKDIR: %s could not be removed. "
		"(Maybe removed by other invocation or by mistake?)\n"
		" Exiting...\n", LOCKDIR);
	return;
      }
  }

  // close sock ?
  // upnp_proxy_exec(UPNP_PROXY_TERM, NULL, 0);

}

/* ipfw cannot store descriptions and timestamp for port mappings so we keep
 * our own list in memory */
struct mapping_desc_time {
	struct mapping_desc_time * next;
	unsigned int timestamp;
	unsigned short eport;	/* looks that eport and *INTERNAL* port is the same. */
	short proto;
	char desc[];
};

static struct mapping_desc_time * mappings_list = NULL;

/* add an element to the port mappings descriptions & timestamp list */
static void
add_desc_time(unsigned short eport, int proto,
              const char * desc, unsigned int timestamp)
{
	struct mapping_desc_time * tmp;
	size_t l;
	if(!desc)
		desc = "miniupnpd";
	l = strlen(desc) + 1;
	tmp = malloc(sizeof(struct mapping_desc_time) + l);
	if(tmp) {
		/* fill the element and insert it as head of the list */
		tmp->next = mappings_list;
		tmp->timestamp = timestamp;
		tmp->eport = eport;
		tmp->proto = (short)proto;
		memcpy(tmp->desc, desc, l);
		mappings_list = tmp;
	}
}

/* remove an element to the port mappings descriptions & timestamp list */
static void
del_desc_time(unsigned short eport, int proto)
{
	struct mapping_desc_time * e;
	struct mapping_desc_time * * p;
	p = &mappings_list;
	e = *p;
	while(e) {
		if(e->eport == eport && e->proto == (short)proto) {
			*p = e->next;
			free(e);
			return;
		} else {
			p = &e->next;
			e = *p;
		}
	}
}

/* go through the list and find the description and timestamp */
static void
get_desc_time(unsigned short eport, int proto,
              char * desc, int desclen,
              unsigned int * timestamp)
{
	struct mapping_desc_time * e;

	for(e = mappings_list; e; e = e->next) {
		if(e->eport == eport && e->proto == (short)proto) {
			if(desc)
				strlcpy(desc, e->desc, desclen);
			if(timestamp)
				*timestamp = e->timestamp;
			return;
		}
	}
}

/* --- */
int add_redirect_rule2(
	const char * ifname,
	const char * rhost,
	unsigned short eport,
	const char * iaddr,
	unsigned short iport,
	int proto,
	const char * desc,
	unsigned int timestamp)
{
  // struct ip_fw rule;
  int r = 0;

  if (upnp_proxy_validate_protocol(proto) < 0)
    return -1;

  if (upnp_proxy_validate_ifname(ifname) < 0)
    return -1;



  // 
  // unsigned short eport, ...  external port #.
  // const char * iaddr, ... ??? internal ip address ???
  // unsigned short iport, ... internal port #?
  //

  // int proto, ... protocol (UDP or TCP)
  // const char * desc, ... description (need to copy (i.e., malloc() and copy)?)
  //     add_desc_copy() does the malloc() and memcpy().
  // unsigned int timestamp  ... timestamp for lease processing?
  //

  syslog(LOG_INFO, "add_redirect_rule2:\n");
  syslog(LOG_INFO, "   protocol: %s, ifname: %s\n", proto == IPPROTO_UDP ? "UDP" : "TCP", 
	 ifname);
  syslog(LOG_INFO, "   iaddr: <<%s>>\n", iaddr);
  syslog(LOG_INFO, "   eport: %d, iport: %d\n", eport, iport);
  syslog(LOG_INFO, "   desc:  <<%s>>\n", desc);
  syslog(LOG_INFO, "   timestamp:        %d\n", timestamp);
	  
  /* 今の UPNP proxy のadd rule に近い */
  /*  check は eport == iport */

  /* rhost というのが外側みたいだ。 */

  if (rhost && rhost[0] != '\0') {
    syslog(LOG_INFO, "rhost: <<%s>>\n", rhost);
  }

  if(eport != iport)
    {
      syslog(LOG_ERR, "error: Does not support eeport(%d) != iport(%d)\n", eport, iport);
      UpnpProxy_SampleUtil_Print("*** Error: Does not support eport(%d) != iport(%d)\n", eport, iport);
      return -1;
    }

  /* Rule を設定する。うまくいったら add_desc_time */

  r = AUX_upnp_redirect (eport, iaddr, iport, 
			 proto == IPPROTO_TCP ? "TCP" : "UDP" , 
			 desc, timestamp /*leaseduration*/
			 );

  /* add an element to the port mappings descriptions & timestamp list */

  if(r >= 0)
    add_desc_time(eport, proto, desc, timestamp);
  return r;
}



/* get_redirect_rule () is called by ../upnpredirect.c */

/* get_redirect_rule()
 * return value : 0 success (found)
 * -1 = error or rule not found */
int get_redirect_rule(
	const char * ifname,	/* IN */
	unsigned short eport,	/* IN */
	int proto,		/* IN */
	char * iaddr,		/* OUT */
	int iaddrlen,		/* IN */
	unsigned short * iport, /* OUT */
	char * desc,		/* OUT */
	int desclen,		/* OUT */
	char * rhost,		/* OUT */
	int rhostlen,		/* IN */
	unsigned int * timestamp, /* OUT */
	u_int64_t * packets,	  /* OUT */
	u_int64_t * bytes)	  /* OUT */
{
  int i;
  /* int j; */
  char *protocol;
  syslog(LOG_INFO, "get_redirect_rule:\n");
  syslog(LOG_INFO, "    eport = %d, proto = %d, ifname=<<%s>>\n", eport, proto, ifname);

  if (upnp_proxy_validate_protocol(proto) < 0)
    return -1;

  if (upnp_proxy_validate_ifname(ifname) < 0)
    return -1;

  if (timestamp)
    *timestamp = 0;

  protocol = ((proto == IPPROTO_TCP) ? "TCP" : "UDP");


  // if protocol and external port matches,
  // return the associated information for the
  // interface/nat
  // packet count
  // byte count,
  // internal port *UPNP proxy uses the same eport
  // ip ... external address ?
  // rhost ... internal address ?! (Meaning is reversed in miniupnd?)

  // TODO/FIXME: packet count, and byte count must
  // be incremented artificially so that the
  // mapping is not removed automatically by miniupnpd.
  //
	    
  for (i = 0; i < RULESMAX; i++)
    {
      MYREDIRECT *mp;
      mp = &redirecttable[i];
      if(verbose > 1)
	UpnpProxy_SampleUtil_Print 
	("info: i=%d, used=%d, externalPort=%d, protocol=%s\n",
	 i, mp->used, mp->externalPort, mp->protocol);

      if (mp->used && mp->externalPort == eport
	  && strncmp (mp->protocol, protocol, 3) == 0)
	{
	  // found
	  if(verbose > 1)
	    UpnpProxy_SampleUtil_Print ("Found match at  i=%d\n", i);

	  if(iport != NULL)
	    *iport = mp->internalPort;
	  /* *leasetimep = mp->leasetime; */
	  
	  /* meaning of rhost and IP seems to be reversed from UPNP Proxy! */
	  if(rhost != NULL && rhostlen > 0)
	    strncpy (rhost, mp->internalIp, min(32, rhostlen));
	  strncpy (iaddr, "", iaddrlen);
	  if(desc != NULL)
	    strncpy (desc, mp->desc, min(desclen, ENTITYLEN));
	  /* *leasep = mp->leasetime; */
	  if(packets != NULL)
	    *packets =   ++(mp->pcount); /* dummy packet count: incremented on read */
	  if(bytes != NULL)
	    *bytes = ++(mp->bcount);    /* dummy byte count: incremented on read */

	  syslog(LOG_INFO, "    Found: rhost=<<%s>>, iaddr=<<%s>>, desc=<<%s>>, *packets=%lld, *bytes=%lld",
		 rhost? rhost : "{NULL}", 
		 iaddr? iaddr : "{NULL}", 
		 desc ?  desc : "{NULL}", 
                 (u_int64_t)(mp->pcount ++), 
		 (u_int64_t)(mp->bcount ++));

	  return 0;
	}
    }

  syslog(LOG_INFO, "    Not Found");
  return -1;


#if 0
  /* Original code in ipfwrdr.c */

  for (i=0; i<total_rules-1; i++) {
    const struct ip_fw const * ptr = &rules[i];
    if (proto == ptr->fw_prot && eport == ptr->fw_uar.fw_pts[0]) {
      if (packets != NULL)
	*packets = ptr->fw_pcnt;
      if (bytes != NULL)
	*bytes = ptr->fw_bcnt;
      if (iport != NULL)
	*iport = ptr->fw_fwd_ip.sin_port;
      if (iaddr != NULL && iaddrlen > 0) {
	/* looks like fw_out_if.fu_via_ip is zero */
	/*if (inet_ntop(AF_INET, &ptr->fw_out_if.fu_via_ip, iaddr, iaddrlen) == NULL) {*/
	if (inet_ntop(AF_INET, &ptr->fw_fwd_ip.sin_addr, iaddr, iaddrlen) == NULL) {
	  syslog(LOG_ERR, "inet_ntop(): %m");
	  goto error;
	}
      }
      if (rhost != NULL && rhostlen > 0) {
	if (ptr->fw_src.s_addr == 0)
	  rhost[0] = '\0';
	else if (inet_ntop(AF_INET, &ptr->fw_src.s_addr, rhost, rhostlen) == NULL) {
	  syslog(LOG_ERR, "inet_ntop(): %m");
	  goto error;
	}
      }
      /* And what if we found more than 1 matching rule? */
      /* Right now, miniupnd stops at the first match. */ 
      upnp_proxy_free_ruleset(&rules);
      get_desc_time(eport, proto, desc, desclen, timestamp);
      return 0;
    }
  }

 error:;
  // if (rules != NULL)
  //  upnp_proxy_free_ruleset(&rules);
  return -1;

#endif

}



/* this is used only on linux in upnpredirect.c */
int 
delete_redirect_and_filter_rules(unsigned short eport,
				     int proto)
{
  if(verbose > 1)
    syslog(LOG_ERR, "delete_redirect_and_filter_rules: eport =%d, proto=%d\n",
	    eport, proto);
  return delete_redirect_rule ("dummy", eport, proto);
}

int delete_redirect_rule(
	const char * ifname,
	unsigned short eport,
	int proto)
{
  // int i;
  // int count_rules;
  //int  total_rules = 0;
  // struct ip_fw * rules = NULL;
  int rc;

  if(verbose > 1)
    syslog(LOG_INFO, "delete_redirect_rules: ifname=<<%s>>, eport =%d, proto=%d\n",
	    ifname, eport, proto);

  if (upnp_proxy_validate_protocol(proto) < 0)
    return -1;

  if (upnp_proxy_validate_ifname(ifname) < 0)
    return -1;

#if 0
  do {
    count_rules = upnp_proxy_fetch_ruleset(&rules, &total_rules, 10);
    if (count_rules < 0)
      goto error;
  } while (count_rules == 10);

  // Store into rules list, all the forward rulesets.
  // total_rules - 1 is the number of rules?
  // valid rules are from rules[0] to rules[total_ruls-2].

#endif

  // if protocol and external port matches,
  // delete that rule.

  rc = UpnpProxy_upnp_delete_redirection (eport, proto == IPPROTO_TCP ? "TCP" : "UDP");

  if (rc != 0)
    goto error;

  del_desc_time(eport, proto);

  return 0;

#if 0
  for (i=0; i<total_rules-1; i++) {
    const struct ip_fw const * ptr = &rules[i];
    if (proto == ptr->fw_prot && eport == ptr->fw_uar.fw_pts[0]) {
      if (upnp_proxy_exec(UPNP_PROXY_DEL, (struct ip_fw *)ptr, sizeof(*ptr)) < 0)
	goto error;
      /* And what if we found more than 1 matching rule? */
      upnp_proxy_free_ruleset(&rules);
      del_desc_time(eport, proto);
      return 0;
    }
  }
#endif

 error:
  // if (rules != NULL)
  //  upnp_proxy_free_ruleset(&rules);

  return -1;
}

int add_filter_rule2(
	const char * ifname,
	const char * rhost,
	const char * iaddr,
	unsigned short eport,
	unsigned short iport,
	int proto,
	const char * desc)
{
	return 0; /* nothing to do, always success */
}

int delete_filter_rule(
	const char * ifname,
	unsigned short eport,
	int proto)
{
	return 0; /* nothing to do, always success */
}

int get_redirect_rule_by_index(
	int index,
	char * ifname,
	unsigned short * eportp,
	char * iaddr,
	int iaddrlen,
	unsigned short * iportp,
	int * protop,
	char * desc,
	int desclen,
	char * rhost,
	int rhostlen,
	unsigned int * timestamp,
	u_int64_t * packets,
	u_int64_t * bytes)
{
  // int total_rules = 0;
	struct ip_fw * rules = NULL;
	int rc;

	if (index < 0) /* TODO shouldn't we also validate the maximum? */
		return -1;

	if(timestamp)
		*timestamp = 0;

	//
	// TODO/FIXME: it seems that index starts at 0 when search begins.
	//

	syslog(LOG_INFO, "get_redirect_rule_by_index: index=%d\n", index);

	// upnp_proxy_fetch_ruleset(&rules, &total_rules, index + 1);

	{
	  int eport;
	  int iport;
	  char protoname[4];
	  rc = UpnpProxy_upnp_get_redirection_infos_by_index (index, /* out */
							    &eport, /* in */
							    protoname, /* in */
							    &iport,
							    iaddr,
							    iaddrlen,
							    desc,
							    desclen, 
							      (signed int *) timestamp);

	  if (rc != 0)
	    goto error;

	  *eportp = eport;
	  *iportp = iport;
	  *protop = (strcmp(protoname, "TCP") == 0) ? IPPROTO_TCP : IPPROTO_UDP;
	}

	// ifname copy
	// strlcpy(ifname, ptr->fw_in_if.fu_via_if.name, IFNAMSIZ);
	// if (packets != NULL)
	// *packets = ptr->fw_pcnt;
	// if (bytes != NULL)
	// *bytes = ptr->fw_bcnt;
	// if (iport != NULL)
	// *iport = ptr->fw_fwd_ip.sin_port;
	// if (iaddr != NULL && iaddrlen > 0) {
	// /* looks like fw_out_if.fu_via_ip is zero */
	// 
	// if (rhost != NULL && rhostlen > 0) {
	// if (ptr->fw_src.s_addr == 0)
	// rhost[0] = '\0';
	// else if (inet_ntop(AF_INET, &ptr->fw_src.s_addr, rhost, rhostlen) 

	//upnp_proxy_free_ruleset(&rules);

	get_desc_time(*eportp, *protop, desc, desclen, timestamp);

	return 0;

error:
	if (rules != NULL)
		upnp_proxy_free_ruleset(&rules);
	return -1;
}


/* upnp_get_portmappings_in_range()
 * return a list of all "external" ports for which a port
 * mapping exists */
unsigned short *
get_portmappings_in_range(unsigned short startport,
                          unsigned short endport,
                          int proto,
                          unsigned int * number)
{
	unsigned short * array = NULL;
	unsigned int capacity = 128;
	// int i, count_rules, total_rules = 0;
	// struct ip_fw * rules = NULL;
	int j;

	if (upnp_proxy_validate_protocol(proto) < 0)
		return NULL;

#if 0
	do {
		count_rules = upnp_proxy_fetch_ruleset(&rules, &total_rules, 10);
		if (count_rules < 0)
			goto error;
	} while (count_rules == 10);
#endif

	array = calloc(capacity, sizeof(unsigned short));
	if(!array) {
		syslog(LOG_ERR, "get_portmappings_in_range() : calloc error");
                goto error;
	}

	*number = 0;

	// total_rules = upnp_get_portmapping_number_of_entries ();

	for (j = 0; j < RULESMAX; j++)
	  if (redirecttable[j].used )
	    {
	      int eport;
	      MYREDIRECT *mp;
	      mp = &redirecttable[j];
	      eport = mp->externalPort;
	      if( (   proto == (strcmp(mp->protocol, "TCP")== 0) ? IPPROTO_TCP : IPPROTO_UDP)
		  &&  startport <= eport
		  &&  eport <= endport ) {
		if(*number >= capacity) {
		  capacity += 128;
		  array = realloc(array, sizeof(unsigned short)*capacity);
		  if(!array) {
		    syslog(LOG_ERR, "get_portmappings_in_range() : realloc(%lu) error", (long) sizeof(unsigned short)*capacity);
		    *number = 0;
		    goto error;
		  }
		}
		array[*number] = eport;
		(*number)++;
		
	      }
	    }

error:
	// if (rules != NULL)
	// 	upnp_proxy_free_ruleset(&rules);

	return array;
}

