/*
 * $Id: ix2015-func.c 
 *
 * This file is included in ../ix2015/ipfwrdr.c
 *
 *
 * Changed from the original upnp proxy routines.
 *
 *   1. took out mutex_lock/unlock routines.
 *   2. Changed the location of the following. From "./" to "../ix2015/".
 *            upnp-auxiliary.pl -> ix2015/upnp-auxiliary.pl
 *
 *            cf. wait-usec stays in the main directory in order to
 *                avoid the modification of Makefile.
 *                Makefile needs to be changed to link different library
 *                -lrt under Solaris.
 *                The Makefile in the main directory already needs to be
 *                switched under linux and solaris, and so the difference
 *                of library is noted there. 
 */

/*
 * snprintf ... stdio
 */
#include <stdio.h>

#include <assert.h>

/* strcpy */
#include <string.h>

/*  strcasecmp */
#include <strings.h>

/* va_start, etc.*/
#include <stdarg.h>

/* gettimeofday, etc. */
#include <sys/time.h> 

/* system */
#include <stdlib.h>

/* ECONNREFUSED */
#include <errno.h>

/* inet_aton and friends, and related data types.
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


// ----------------------------------------

#define min(x,y) (((x) > (y)) ? (y) : (x))


// TODO/FIXME: We should have a safe place and use an absolute path
#define IGDNATSAVEFILE    "./igd-dump.txt"
#define ROUTER_NATFILE    "./router-dump.txt"

#define RULESMAX 20
#define ENTITYLEN 128

#if 0
/* miniupnpd seems to require certain info about the interface. */
struct interface_info
{
  int uptime;
  char uptime_str[128];		/* image */
  int packets; /* dummy : each time this is read, this should be
		  incremented. */
  int bytes; /* dummy : each time this is read, this should be incremented. */
  int eaddr; /* address. */
  char eaddr_str[128];		/* string image */
} ext_interface_info;
#endif

extern 	int WANIPConnection_Set_Uptime (char *);		  /* dont notify */
extern  int WANIPConnection_Set_ExternalIPAddress (char *); /* NOTIFY */
extern  int WANIPConnection_Set_PortMappingNumberOfEntries (char *); /* Notify */

/*
 * to control debug verbosity.
 */ 
extern int verbose ; 		/* in main-daemon.c  */

struct timeval last_call_of_system;

typedef struct MYREDIRECT
{
  char externalhost[ENTITYLEN];
  int externalPort;
  char internalIp[32];
  int internalPort;		/* Current restriction: the same as external */
  char desc[ENTITYLEN];
  char protocol[4];		/* TCP/UDP */
  int enabled;			/* enable/disabled. NOT USED for now*/
  int leasetime;
  // int mutable;			/* should not be removed. NOT USED */
  // int in_router;             /* already in the router at startup */
  int used;			/* entry is in use or not */
  int externally_visible_index;	/* counting used entry upward from 0 */

  int pcount;			/* dummy packet count: incremented on read */
  int bcount;			/* dummy byte count: incremented on read */
} MYREDIRECT;

static MYREDIRECT redirecttable[RULESMAX];

//
// ??? when do we initialie redirecttable[] 
//


int UpnpProxy_SampleUtil_Print(const char *fmt, ...)
{
#define MAX_BUF (8 * 1024)
	va_list ap;
	static char buf[MAX_BUF];
	int rc;

	/* Protect both the display and the static buffer with the mutex */
#if 0
	ithread_mutex_lock(&display_mutex);
#endif

	va_start(ap, fmt);
	rc = vsnprintf(buf, MAX_BUF, fmt, ap);
	va_end(ap);
	// if (gPrintFun)
	//     gPrintFun("%s", buf);
	fprintf(stderr, "%s", buf);

#if 0
	ithread_mutex_unlock(&display_mutex);
#endif

	return rc;
}

//
// After a successful "DEL" operation, often telnet login is
// refused. So decided to add longer wait time after a DEL operation.
//
// Delay if 0.4 sec has not passed since the previous call of system(). 
// 0.4 sec was enough to add NAT mappings : no system() failed.
// 0.3 sec : one system call failed in several dozen tests.
// usleep may have alarm/signal contention issue. Caused SIGSEGV probably
// in  httpparser (built-in web server).
// So we used nanosleep(). This is not unfortunately sync-signal-safe, and
// so we opted to use an external program for delay.
//
// Also we now retry three times. Retrying once solves the
// connection refused issue completely during test runs.
// 
static void
delay_system_if_too_rapid(int is_add)
{
  int rc;
  struct timeval current_time;
  unsigned long delta;
  unsigned long add_delay = (!is_add) ? 2000000 : 1000000;

  rc = gettimeofday(&current_time, NULL);
  if(rc) {
    UpnpProxy_SampleUtil_Print("gettimeofday failed: rc=%d\n", rc);
    return;
  }
  //  struct timeval {
  // time_t      tv_sec;     /* 秒 */
  // suseconds_t tv_usec;    /* マイクロ秒 */
  //};
  if( current_time.tv_sec - last_call_of_system.tv_sec >= 2)
    return;				/* OK */

  delta = (current_time.tv_sec - last_call_of_system.tv_sec) * 1000000
    + (current_time.tv_usec - last_call_of_system.tv_usec);
  if(delta < 500000 + add_delay)
    {
#if 0
      /* Using nanosleep() may interfere with sigwait(), etc.. 
       * So, this approach was abolished.
       */
      long t = 500000 + add_delay - delta + 50000; 
      struct timespec req;
      struct timespec rem;
      UpnpProxy_SampleUtil_Print("Delaying. nanosleep(%d)\n", t * 1000);
      req.tv_sec = t / 1000000;
      req.tv_nsec = t*1000 - req.tv_sec * 100000000;
      rc = nanosleep(&req,&rem);
      if(!rc)
	UpnpProxy_SampleUtil_Print("nanosleep() returned rc=%d\n", rc);
#else
      char cmd[128];
      long t = 500000 + add_delay - delta + 50000; 
      UpnpProxy_SampleUtil_Print("Delaying. %d microseconds \n", t );
      snprintf(cmd, 128, "./wait-usec %ld ", t);
      rc = system(cmd);
      UpnpProxy_SampleUtil_Print("system(%s) returned %d\n", cmd, rc);
#endif
    }
}

static
void  
record_current_time(void)
{
  int rc;
  rc = gettimeofday(&last_call_of_system, NULL);
  if(rc) 
    UpnpProxy_SampleUtil_Print("gettimeofday failed: rc=%d\n", rc);
}

//
// Use of SystemMutex is redundant in the current code (as of Sept 2009) 
// since the IDG now runs with DevicMeutex
// and also with NatRulesMutex.
// But the code may change in the future and it doesn't hurt to
// be careful in advance.
//


static
int
system_with_delay(char cmd[], int is_add)
{
  int rc;
  int retry = 0;
#if 0
  ithread_mutex_lock (&SystemMutex);
#endif
  //
  // often we fail with WEXITSTATUS(rc) == 111 :  connection refused.
  // We retry three times.
  // We may succeed after a pause.
  //
 retry:
  delay_system_if_too_rapid(is_add);
  rc = system(cmd);
  record_current_time();
  // ECONNREFUSED 111. connection refused.
  // EEXIST        17.  lock directory could not be created.
  // 2, 255 ... perl syntax error, etc..
  if(WEXITSTATUS (rc) == ECONNREFUSED || WEXITSTATUS(rc) == EEXIST) 
    { 
      if (retry++ < 3)
	{
	  UpnpProxy_SampleUtil_Print("System retrying... retry=%d\n", retry);
	  goto retry;
	}
      else
	UpnpProxy_SampleUtil_Print("System retry failed.\n");
    }
#if 0
  ithread_mutex_unlock (&SystemMutex);
#endif
  return rc;
}




/*
 * # of mapping entries.
 * also renumber the visible indices.
 *
 * Not THREAD-SAFE. Callers beware.
 */
int
upnp_get_portmapping_number_of_entries (void)
{
  int i, sum;

  sum = 0;
  for (i = 0; i < RULESMAX; i++)
    {
      if (redirecttable[i].used)
	{
	  redirecttable[i].externally_visible_index = sum;
	  sum++;
	}
      else
	redirecttable[i].externally_visible_index = -1;
    }

  return sum;
}

// ADD:
// ip access-list permit-napt-in permit PROTOCOL src any sport any dest any dport eq PORT
// 
// For each interface :
// ip natp static INTERNALIP PROTOCOL PORT
// ip napt service H$INTERNALIP$PORT$PROTOCOL INTERNALIP none PROTOCOL PORT

#define IX2015CMDLEN 128

static char ix2015_rules[5][IX2015CMDLEN];
static char ix2015_service[IX2015CMDLEN];

#define ROUTERCMDLEN 256
static char routercmd[ROUTERCMDLEN];

// Simple Security check: based on port number
//
// TODO/FIXME: maybe security should be  based on 
// the pair of (protocol, port) instead of just a port number.
// For now, it is OK.
static int
is_restricted (int port)
{
  /* no check, any port is OK */
  return 0;

#if 0

  int i;
  static int restricted_port[] = {
    137, 138, 139,
    53,
    /* We may want to prohibit < 1024 mapping */
    1, 11, 15, 20, 21, 23, 67,
    68, 69, 70, 79, 87, 95, 111,
    135, 144, 161, 162, 177, 220,
    445, 512, 513, 514, 515, 517,
    518, 520, 540,
    1025, 1243,
    2000, 2049, 2766,
    6257, 6665, 6666, 6667, 6668, 6669, 6699,
    7743,
    12345,
    27374,
    31785, 31789, 31791,
  };

  for (i = 0; i < sizeof (restricted_port) / sizeof (restricted_port[0]); i++)
    if (port == restricted_port[i])
      return 1;

  /* We may want to prohibit < 1024 mapping */
#if 0
  if (port < 1024)
    return 1;
#endif

#endif

  return 0;
}


//
// A function to create a dummy service name for ip napt syntax.
//
// external port #, protocol, internalIPaddress -> servicename
//
static char *
aux_ix2015_servicename (int eport, char protocol[], char internalip[])
{
  int i;
  int j;
  char internalip2[32];
  // replace "." with "d".
  // remove spaces at the end.
  for (i = 0, j = 0; i < 32; i++)
    {
      if (internalip[i] == '.')	/* dot */
	internalip2[j++] = 'd';
      else if (internalip[i] == ' ' || internalip[i] == '\t')	/* space */
	;			/* ignore */
      else if (internalip[i] == '\0')	/* end */
	{
	  internalip2[j] = '\0';
	  break;
	}
      else
	internalip2[j++] = internalip[i];
    }

  snprintf (ix2015_service, IX2015CMDLEN, "h%se%d%s", internalip2, eport,
	    protocol);
  return ix2015_service;
}

//
// Rules to be written to IX2015
//
// Actually, this is now handled by external upnp-auxiliary.pl script.
// But for the sake of completeness, and historical reasons,
// and to give a sample code for different future scripts, 
// I retain the code here as well.
//
static void
aux_ix2015_rules (char array[5][IX2015CMDLEN], 
		  int remove,	/* 0 for addition, non-zero for removal */
		  int eport,	/* port number as integer */
		  char protocol[],	/* TCP, UDP  */
		  char internalip[]	/* ip address as string */
		  )
{
  char *prefix = "";
  char *lowercase_protocol = "udp";
  if (remove)
    prefix = "no ";

  assert (strcasecmp (protocol, "tcp") == 0
	  || strcasecmp (protocol, "udp") == 0);

  if (strcasecmp (protocol, "tcp") == 0)
    lowercase_protocol = "tcp";

  snprintf (&array[0][0], IX2015CMDLEN,
	    "%sip access-list permit-napt-in permit %s src any sport any dest any dport eq %d",
	    prefix, lowercase_protocol, eport);

  snprintf (&array[1][0], IX2015CMDLEN, "For each interface:");
  snprintf (&array[2][0], IX2015CMDLEN,
	    "%sip napt static %s %s %d", prefix, internalip,
	    lowercase_protocol, eport);
  snprintf (&array[3][0], IX2015CMDLEN, "%sip napt service %s %s none %s %d",
	    prefix, aux_ix2015_servicename (eport, lowercase_protocol,
					    internalip), internalip,
	    lowercase_protocol, eport);
}


//
// add NAT mapping rule
//

static int
ix2015_add_mapping (int eport, char protocol[], char internalip[])
{
  int i;
  int rc;

  char lowercase_protocol[4];

  UpnpProxy_SampleUtil_Print ("IX2015 ADD: eport=%d, protocol=%s, internalip=%s\n",
		    eport, protocol, internalip);

  aux_ix2015_rules (ix2015_rules, 0, eport, protocol, internalip);

  UpnpProxy_SampleUtil_Print ("IX2015 ADD: BEGIN\n");
  for (i = 0; i < 4; i++)
    {
      UpnpProxy_SampleUtil_Print ("IX2015 ADD: %s\n", &ix2015_rules[i][0]);
    }
  UpnpProxy_SampleUtil_Print ("IX2015 ADD: END\n");

  if (strcmp (protocol, "TCP") == 0)
    strcpy (lowercase_protocol, "tcp");
  else
    strcpy (lowercase_protocol, "udp");
  snprintf (routercmd, ROUTERCMDLEN,
	    "env LANG=C mv -f /tmp/a.action /tmp/a.action.old; "
	    "env LANG=C perl ix2015/upnp-auxiliary.pl -action add "
	    "-eport %d -internalip %s -protocol %s -servicename %s   > /tmp/a.action ",
	    eport, internalip, lowercase_protocol,
	    aux_ix2015_servicename (eport, lowercase_protocol, internalip));

  UpnpProxy_SampleUtil_Print ("****************************************\n");
  UpnpProxy_SampleUtil_Print ("Calling <<%s>>\n", routercmd);
  rc = system_with_delay (routercmd, 1 /* is_add */);
  {
    char errmsg[128];

    bzero(errmsg, 128);

    strerror_r (WEXITSTATUS(rc), errmsg, 128);

    UpnpProxy_SampleUtil_Print ("rc = system(%s) returns \n%d (0x%04x) "
		      "[WEXITSTATUS(rc) = %d, %s]\n",
		      routercmd, rc, rc, WEXITSTATUS(rc),
		      errmsg);
  }
  UpnpProxy_SampleUtil_Print ("****************************************\n");

  return rc;
}

//
// remove NAT mapping rule
//
static int
ix2015_remove_mapping (int eport, char protocol[], char internalip[])
{
  int i;
  int rc;

  char lowercase_protocol[4];


  UpnpProxy_SampleUtil_Print ("IX2015 REMOVE: eport=%d, protocol=%s, internalip=%s\n",
		    eport, protocol, internalip);

  aux_ix2015_rules (ix2015_rules, 1, eport, protocol, internalip);

  UpnpProxy_SampleUtil_Print ("IX2015 DEL: BEGIN\n");
  for (i = 0; i < 4; i++)
    {
      UpnpProxy_SampleUtil_Print ("IX2015 DEL: %s\n", &ix2015_rules[i][0]);
    }
  UpnpProxy_SampleUtil_Print ("IX2015 DEL: END\n");

  if (strcmp (protocol, "TCP") == 0)
    strcpy (lowercase_protocol, "tcp");
  else
    strcpy (lowercase_protocol, "udp");
  snprintf (routercmd, ROUTERCMDLEN,
	    "env LANG=C mv -f /tmp/t.action /tmp/t.action.old; "
	    "env LANG=C perl ix2015/upnp-auxiliary.pl -action del -eport %d -internalip %s "
	    "-protocol %s -servicename %s > /tmp/t.action",
	    eport, internalip, lowercase_protocol,
	    aux_ix2015_servicename (eport, lowercase_protocol, internalip));

  UpnpProxy_SampleUtil_Print ("****************************************\n");
  UpnpProxy_SampleUtil_Print ("Calling <<%s>>\n", routercmd);
  rc = system_with_delay (routercmd, 0 /* is_add */ );
  {
    char errmsg[128];
    strerror_r (WEXITSTATUS (rc), errmsg, 128);
    UpnpProxy_SampleUtil_Print ("rc = system(%s) returns \n%d (0x%04x) "
		      "[WEXITSTATUS(rc) = %d, %s]\n",
		      routercmd, rc, rc, WEXITSTATUS (rc),
		      errmsg);
  }

  UpnpProxy_SampleUtil_Print ("****************************************\n");

  return rc;
}

//
// Dump internal NAT mapping table.
//
// Saved file format:
// XNport,ipaddress,proto,description...
//
void
IGD_NAT_rule_dump (void)
{
  int i;
  FILE *fp;
  int rc;

  UpnpProxy_SampleUtil_Print ("IGD_NAT_rule_dump() called.\n");

#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  fp = fopen (IGDNATSAVEFILE, "wb");
  if (fp == NULL)
    {
      perror (IGDNATSAVEFILE);
      UpnpProxy_SampleUtil_Print ("Saving file could not be opened. Skipped.\n");
      goto error_exit;
    }

  /* FILE I/O lock. Just in case... */
#if 0
  ithread_mutex_lock (&display_mutex);
#endif

  for (i = 0; i < RULESMAX; i++)
    {
      struct MYREDIRECT *mp;
      mp = &redirecttable[i];
      if (!mp->used)
	continue;

      fprintf (fp, "XN%d,%s,%s,%s\n",
	       mp->externalPort, mp->internalIp, mp->protocol, mp->desc);
    }

  rc = fclose (fp);
  if (rc != 0)
    perror ("");

#if 0
  ithread_mutex_unlock (&display_mutex);
#endif

 error_exit:;
#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

}

//
// Read a line from external NAT mapping file.
// Data Format on each line
// XNportnum,ipaddr,protocol,
// if desc_is_sought is non-zero, description string is also read.
//
int
IGD_NAT_rule_load_NAT_line (char line[],
			    int *eportp,
			    char ipaddr[],
			    int ipaddrlen,
			    char protocol[],
			    int protocollen,
			    int desc_is_sought, 
			    char desc[], 
			    int desclen)
{
  char *np;
  // int t;
  // int ep;
  char *cp;
  int len;

  assert (line[0] == 'X' && line[1] == 'N');

  // strip the trailing newline
  if (strlen (line) >= 1 && line[strlen (line) - 1] == '\n')
    line[strlen (line) - 1] = '\0';

  // XN5xxxx,192.168.0.abc,upd,
  // UpnpProxy_SampleUtil_Print ("IGD_NAT_rule_load_NAT_line called:\nline=%s\n", line);
  UpnpProxy_SampleUtil_Print ("line=%s\n", line);
  np = &line[2];

  // There was a bug. ipaddr was scanned here by mistake and when
  // it read "peercast2", it overwrote ipaddr(size is 4) and corrupt variable i of
  // the calling routine!

  // Port
  sscanf (np, "%d", eportp);

  // obtain ipaddr by splitting the tokens separated by ",".
  np = strchr (np, ',') + 1;
  cp = strchr (np, ',');
  if(cp == NULL) 
    {
      UpnpProxy_SampleUtil_Print("Missing a comma after ipaddr field.\n");
      return -1;
    }
  len = cp - np;
  len = min (len, ipaddrlen - 1);
  bcopy (np, ipaddr, len);
  ipaddr[len] = '\0';

  np = cp + 1;
  cp = strchr (np, ',');
  if(cp == NULL) 
    {
      UpnpProxy_SampleUtil_Print("Missing a comma after protocol field.\n");
      return -1;
    }
  len = cp - np;
  len = min (cp - np, protocollen - 1);
  bcopy (np, protocol, len);
  protocol[len] = '\0';

  if (desc_is_sought)
    strncpy (desc, cp + 1, desclen);

#if 0
  if (!desc_is_sought)
    UpnpProxy_SampleUtil_Print ("Port=%d, ipaddress=%s, protocol=%s\n",
		      *eportp, ipaddr, protocol);
  else
    UpnpProxy_SampleUtil_Print ("Port=%d, ipaddress=%s, protocol=%s, desc=<<%s>>\n",
		      *eportp, ipaddr, protocol, desc);
#endif

  return 0;
}

//
// On startup, load from both the dump files from the real router
// and the dump from the previous run of this program and
// does something clever (like associating the description from
// the former program dump to the current router mapping).
//
// returns a negative value if the router data is not available.
//
int
IGD_NAT_rule_load (void)
{
  int i;
  int j;
  FILE *fp;
  int rc;
  char ipaddr[32];
  char protocol[4];
  char desc[128];
  int eport;
  // char *np;
  struct MYREDIRECT *mp;
  int retval = 0;

#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  bzero (&redirecttable[0], sizeof (redirecttable));;
  bzero(desc, sizeof(desc));

  UpnpProxy_SampleUtil_Print ("****************************************\n");
  UpnpProxy_SampleUtil_Print
    ("IGD_NAT_rule_load: First part: reading the current router setting.\n");
  UpnpProxy_SampleUtil_Print ("****************************************\n");

  {
    snprintf (routercmd, ROUTERCMDLEN,
	      "env LANG=C mv -f %s %s.old; env LANG=C perl ix2015/upnp-auxiliary.pl > %s",
	      ROUTER_NATFILE, ROUTER_NATFILE, ROUTER_NATFILE);
    UpnpProxy_SampleUtil_Print ("****************************************\n");

    rc = system_with_delay (routercmd, 0 /* is_add */);
    {
      char errmsg[128];
      bzero(errmsg, 128);	/* added for miniupnpd? */
      strerror_r (WEXITSTATUS (rc), errmsg, 128);
      UpnpProxy_SampleUtil_Print ("rc = system(%s) returns \n%d (0x%04x) "
			"[WEXITSTATUS(rc) = %d, %s]\n",
			routercmd, rc, rc, WEXITSTATUS (rc),
			errmsg);
    }

    UpnpProxy_SampleUtil_Print ("****************************************\n");
    if (rc != 0)
      {
	UpnpProxy_SampleUtil_Print
	  ("system() returned error, so loading is skipped.\n");
	retval = -1;
	goto exit_label;  /* don't return yet. We need to release lock */
      }
  }

  fp = fopen (ROUTER_NATFILE, "rb");
  if (fp == NULL)
    {
      perror (ROUTER_NATFILE);
      UpnpProxy_SampleUtil_Print ("Dump file from the external script could not be opened. Skipped.\n");
      retval = -1;
      goto exit_label;
    }

  // i in the next loop is the number of NAT mappings read in. 
  for (i = 0; fgets (routercmd, ROUTERCMDLEN, fp) != NULL; )
    {
      char *np;
      if (routercmd[0] != 'X')
	continue;

      if (strlen (routercmd) >= 1
	  && routercmd[strlen (routercmd) - 1] == '\n')
	routercmd[strlen (routercmd) - 1] = '\0';

      np = &routercmd[2];
      switch (routercmd[1])
	{
	default:
	  UpnpProxy_SampleUtil_Print
	    ("the second letter <<%c>>in router dump is not valid.\n",
	     routercmd[1]);
	  break;
	case 'U':		/* UPTIME */
	  (void) WANIPConnection_Set_Uptime (np); /* dont notify */
	  UpnpProxy_SampleUtil_Print ("Uptime: %s\n", np);
	  break;
	case 'G':
	  (void) WANIPConnection_Set_ExternalIPAddress (np); /* NOTIFY */
	  UpnpProxy_SampleUtil_Print ("ExternalIPaddress: %s\n", np);
	  break;
	case 'N':
	  //UpnpProxy_SampleUtil_Print("i = %d before IGD_NAT_rule_load_NAT_line\n", i); 
	  if (IGD_NAT_rule_load_NAT_line (routercmd, 
					  &eport, 
					  ipaddr, sizeof (ipaddr), 
					  protocol, sizeof (protocol), 
					  0,	// desc_is_sought
					  NULL, 
					  0) < 0)
	    {
	      UpnpProxy_SampleUtil_Print ("The nat data line had syntax error. Ignored.\n");
	      continue;
	    }
	  //UpnpProxy_SampleUtil_Print("i = %d after IGD_NAT_rule_load_NAT_line\n", i); 
	  if (strcasecmp (protocol, "tcp") == 0)
	    strcpy (protocol, "TCP");
	  else if (strcasecmp (protocol, "udp") == 0)
	    strcpy (protocol, "UDP");
	  else
	    {
	      UpnpProxy_SampleUtil_Print ("protocol <<%s>> is INVALID. IGNORED.\n", protocol);
	      continue;
	    }

	  // UpnpProxy_SampleUtil_Print ("Port=%d, ipaddress=<<%s>>, protocol=%s\n",
	  // eport, ipaddr, protocol);
	  // Register as in the router
	  if (i >= RULESMAX)
	    {
	      UpnpProxy_SampleUtil_Print ("Too many nat mapping: i = %d. Ignored\n", i);
	      continue;
	    }
	  if (is_restricted (eport))
	    {
	      UpnpProxy_SampleUtil_Print
		("Port %d is a restricted one, and is not under control of UPnP. Ignored.\n",
		 eport);
	      continue;
	    }
	  //
	  // Check for duplication!  In this sense, we should simply
	  // use 
	  // r = upnp_redirect(eport, int_ip, iport, protocol, desc); Not!
	  // NO. The call will try to register a rule in the router,
	  // which we don't want due to increased network traffic!

	  // check for duplication.
	  /* see for a match  */
	  for (j = 0; j < RULESMAX; j++)
	    {
	      mp = &redirecttable[j];
#if 0
	      UpnpProxy_SampleUtil_Print
		("loop : j=%d, used=%d, externalPort=%d, protocol=%s\n", i,
		 mp->used, mp->externalPort, mp->protocol);
#endif
	      if (mp->used
		  && mp->externalPort == eport
		  && strncmp (mp->protocol, protocol, 4) == 0)
		{
		  if (strncmp (&mp->internalIp[0], ipaddr, 32) == 0
		      && mp->internalPort == eport)
		    {
		      UpnpProxy_SampleUtil_Print
			("ignoring router table entry as it matches an existing redirect at i=%d\n",
			 i);
		      break;
		    }
		  else
		    {
		      // found
		      UpnpProxy_SampleUtil_Print
			("match found: %d %s is already redirected to %s:%d :\nthe latter one is ignored. (But router is then buggy?)\n",
			 eport, protocol, mp->internalIp, mp->internalPort);
		      break;
		    }
		}
	    }			/* for */

	  if (j < RULESMAX)	/* We found a premature match and so skip. */
	    continue;

	  mp = &redirecttable[i];
	  mp->externalPort = eport;
	  mp->internalPort = eport;
	  strncpy (mp->internalIp, ipaddr, 32);
	  strncpy (mp->protocol, protocol, 4);
	  mp->used = 1;
	  i++;			/* increment NAT mapping # */
	  break;		/* case break */

	} /* switch */

    } /* for */

  rc = fclose (fp);
  if (rc != 0)
    perror ("");

  // Read the dump file from the previous session

  UpnpProxy_SampleUtil_Print ("****************************************\n");
  UpnpProxy_SampleUtil_Print
    ("IGD_NAT_rule_load: Second part: reading the previous session dump.\n");
  UpnpProxy_SampleUtil_Print ("****************************************\n");

  fp = fopen (IGDNATSAVEFILE, "rb");
  if (fp == NULL)
    {
      perror (IGDNATSAVEFILE);
      UpnpProxy_SampleUtil_Print ("Loading from %s could not be opened. Skipped.\n",
			IGDNATSAVEFILE);
      goto exit_label;		/* don't return yet. We need to release lock. */
    }

  bzero(routercmd, ROUTERCMDLEN);
  for (i = 0; 
       fgets (routercmd, ROUTERCMDLEN, fp) != NULL; 
       bzero(routercmd, ROUTERCMDLEN), i++  )
    {
      // UpnpProxy_SampleUtil_Print("second loop: i=%d\n", i);

      if (routercmd[0] != 'X')
	{
	  UpnpProxy_SampleUtil_Print
	    ("First letter in file is not X. Ignored.\nline:%s\n", routercmd);
	  continue;
	}

      // np = &routercmd[2];
      if (routercmd[1] != 'N')
	{
	  UpnpProxy_SampleUtil_Print
	    ("the second letter <<%c>> in session dump is not 'N'. Ignored.\n",
	     routercmd[1]);
	  continue;
	}

      IGD_NAT_rule_load_NAT_line (routercmd, &eport, 
				  ipaddr, sizeof (ipaddr), 
				  protocol, sizeof (protocol), 
				  1,	// desc_is_sought
				  desc, 
				  sizeof(desc));
      //UpnpProxy_SampleUtil_Print
      // ("Port=%d, ipaddress=<<%s>>, protocol=%s, desc=<<%s>>\n", eport,
      // ipaddr, protocol, desc);

      // Register as in the router
      if (i >= RULESMAX)
	{
	  UpnpProxy_SampleUtil_Print ("Too many NAT mapping: i = %d. Ignored\n", i);
	  continue;
	}

      if (is_restricted (eport))
	{
	  UpnpProxy_SampleUtil_Print
	    ("Port %d is a restricted one, and is not under control of UPnP. Ignored.\n",
	     eport);
	  continue;
	}

      // look for 'used' entry with the same port, protocol and
      // internalip address mapping.
      // If there is one, then copy the desc to that entry
      // (Well such an entry ought to be also visible, i.e., used.)
      // No match -> warn and ignore. 
      for (j = 0; j < RULESMAX; j++)
	{
	  struct MYREDIRECT *mp;
	  mp = &redirecttable[j];
	  if (mp->used
	      && mp->externalPort == eport
	      && strncmp (mp->internalIp, ipaddr, 32) == 0
	      && strncasecmp (mp->protocol, protocol, 4) == 0)
	    {
	      strncpy (mp->desc, desc, sizeof (mp->desc));
	      break;
	    }
	}

      if (j >= RULESMAX)
	{
	  UpnpProxy_SampleUtil_Print
	    ("Mapping %.256s is not found in the current router rules. Ignored.\n",
	     routercmd);
	}

    } /* for */

  rc = fclose (fp);
  if (rc != 0)
    perror ("");

  UpnpProxy_SampleUtil_Print ("Dump current mapping\n");
  if (upnp_get_portmapping_number_of_entries () <= 0)
    UpnpProxy_SampleUtil_Print
      ("No mapping is availalbe under the control of this program.\n");

  for (i = 0; i < RULESMAX; i++)
    {
      struct MYREDIRECT *mp;
      mp = &redirecttable[i];
      if (!mp->used)
	continue;

      UpnpProxy_SampleUtil_Print ("i=%3d:%-6d,%-16s, %s, %s\n",
			i,
			mp->externalPort,
			mp->internalIp, mp->protocol, mp->desc);
    }

 exit_label:

#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

  return retval;
}


//
// CAUTION:
// redirection table handling should be mutex-protected!
//

/* get_redirect_rule() gets internal IP and port from
 * interface, external port and protocol
 */

/* upnp_redirect() 
 * invokes system-specific action of the redirection.
 * protocol: "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */
static 
int
AUX_upnp_redirect (int eport,
		   const char *iaddr,
		   int iport,
		   const char *protocol, 
		   const char *desc, 
		   int leaseduration)
{
  struct in_addr address;
  int rc;			/* return value from external script */
  int i;
  // int proto;
  int sum;
  char varimage[32];

  MYREDIRECT *mp;

  if(verbose > 0) 
  UpnpProxy_SampleUtil_Print
    ("upnp_get_redirection called: eport=%d, iaddr=%s, iport=%d, protocol=%s, desc=%s\n",
     eport, iaddr, iport, protocol, desc);

  // Very simple sanity check
  if (inet_aton (iaddr, &address) < 0)
    {
      UpnpProxy_SampleUtil_Print ("inet_aton(%s) failed", iaddr);
      return -1;
    }


  // TODO/FIXME: We should have a security mechanism here.
  // checking the mapping (external port, internal port, internal IP address.)

  /* TODO/FIXME */

  /* First  see if there is the same entry */
  /* look for empty slot */

  /* see for a match  */
  for (i = 0; i < RULESMAX; i++)
    {
      mp = &redirecttable[i];
#if 0
      UpnpProxy_SampleUtil_Print
	("loop : i=%d, used=%d, externalPort=%d, protocol=%s\n", i, mp->used,
	 mp->externalPort, mp->protocol);
#endif
      if (mp->used
	  && mp->externalPort == eport
	  && strncmp (mp->protocol, protocol, 4) == 0)
	{
	  if (strncmp (&mp->internalIp[0], iaddr, 32) == 0
	      && mp->internalPort == iport)
	    {
	      UpnpProxy_SampleUtil_Print
		("***!!!*** ignoring redirect request as it matches an "
		 "existing redirect at i=%d (return 0)\n",
		 i);
	      UpnpProxy_SampleUtil_Print
		("***!!!*** (said to help the situation with x360 which "
		 "forgets previous mapping,\n"
		 "***!!!*** and will simply try to reallocate another, "
		 "ending in many mappings.)\n");
	      return 0;
	    }
	  else
	    {
	      // found
	      UpnpProxy_SampleUtil_Print
		("match found: %d %s is already redirected to "
		 "%s:%d (return -2) \n",
		 eport, protocol, mp->internalIp, iport);
	      return -2;
	    }
	}
    }				/* for */

  for (i = 0; i < RULESMAX; i++)
    {
      mp = &redirecttable[i];
      /* look for empty slot */
      if (mp->used)
	continue;

      mp->used = 1;
      mp->externalPort = eport;
      strncpy (mp->internalIp, iaddr, 32);
      mp->internalPort = iport;
      strncpy (mp->protocol, protocol, 4);
      strncpy (mp->desc, desc, ENTITYLEN);
      mp->leasetime = leaseduration;	/* TODO/FIXME */

      rc = ix2015_add_mapping (mp->externalPort, mp->protocol, mp->internalIp);
      if(rc) 
	{
	  UpnpProxy_SampleUtil_Print("Calling external script returned failure. Adding aborted: "
			   "rc=%d, WEXITSTATUS(rc)=%d\n", 
			   rc, 
			   WEXITSTATUS(rc));
	  return -1;
	}

      // renumber the visible indices. (Compact)
      sum = upnp_get_portmapping_number_of_entries ();
      if(verbose > 0)
	UpnpProxy_SampleUtil_Print ("Registering at i=%d\n", i);

      /* TODO/FIXME : may not be desirable to do this in response / action?  */
      snprintf (varimage, 32, "%d", sum);
      (void) WANIPConnection_Set_PortMappingNumberOfEntries (varimage); /* Notify */

      return 0;
    }
  UpnpProxy_SampleUtil_Print ("No more empty slot.\n");
  return -1;
}

int
UpnpProxy_upnp_redirect (int eport,
	       const char *iaddr,
	       int iport,
	       const char *protocol, const char *desc, int leaseduration)
{
  int rc;

#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  rc = AUX_upnp_redirect (eport, iaddr, iport, protocol, desc, leaseduration);

#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

  return rc;
}


static
int
UpnpProxy_upnp_get_redirection_infos (int eport,
			    char *protocol,
			    int *iport,
			    char *iaddr,
			    int iaddrlen,
			    char *desc, int desclen, int *leasetime);

static
int
UpnpProxy_upnp_get_redirection_infos_by_index (int index,
				     int *eport,
				     char *protocol,
				     int *iport,
				     char *iaddr,
				     int iaddrlen,
				     char *desc,
				     int desclen, int *leasetimep);

/* AUX_upnp_delete_redirection()
 * returns: 0 on success
 *          -1 on failure.
 *
 * Non MT-Safe. Protect this with mutex before call.
 */
static
int
AUX_upnp_delete_redirection (int eport, const char *protocol)
{
  // delete rule and filter

  int rc;			/* external script return value. */
  unsigned i = 0;
  int sum;
  MYREDIRECT *mp;
  char varimage[32];

  // renumber           
  sum = upnp_get_portmapping_number_of_entries ();
  if (sum <= 0)
    {
      UpnpProxy_SampleUtil_Print ("no rules (list is empty).\n");
      return -1;
    }

  for (i = 0; i < RULESMAX; i++)
    {
      mp = &redirecttable[i];
      if (mp->used)
	{
	  if (strncmp (mp->protocol, protocol, 4) == 0
	      && mp->externalPort == eport)
	    /* found */
	    break;
	}
    }

  if (i >= RULESMAX)
    return -1;

  rc = ix2015_remove_mapping (mp->externalPort, mp->protocol, mp->internalIp);
  if(rc)
    {
      UpnpProxy_SampleUtil_Print("Calling external script returned failure.: "
		       "rc=%d, WEXITSTATUS(rc)=%d\n", 
		       rc, 
		       WEXITSTATUS(rc));
      return -1;
    }

  mp->used = 0;
  // renumber           
  sum = upnp_get_portmapping_number_of_entries ();

  // lease_file_remove

  // upnp_event_var_change_notify?
  // PortMappingNumberOfEntries

  snprintf (varimage, 32, "%d", sum);

  (void) WANIPConnection_Set_PortMappingNumberOfEntries (varimage); /* Notify */

  return 0;
}

/* upnp_delete_redirection()
 * returns: 0 on success
 *          -1 on failure*/
static
int
UpnpProxy_upnp_delete_redirection (int eport, const char *protocol)
{
  int rc;

#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  rc = AUX_upnp_delete_redirection(eport, protocol);

#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

  return rc;
}


/*
 * upnp_get_redirection_infos(eport, protocol).
 * Non-thread safe version. Protect with mutex before calling this function.
 */
static int
AUX_upnp_get_redirection_infos (int eport,
				char protocol[],
				int *iportp,
				char int_ip[],
				int int_ip_len,
				char desc[], int desc_len, int *leasetimep)
{
  int i;
  MYREDIRECT *mp;
  if(verbose > 1)
    UpnpProxy_SampleUtil_Print
      ("upnp_get_redirection_infos called: eport=%d, protocol=%s\n", 
       eport, protocol);

  for (i = 0; i < RULESMAX; i++)
    {
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

	  *iportp = mp->internalPort;
	  bcopy (mp->internalIp, int_ip, min (32, int_ip_len));
	  bcopy (mp->desc, desc, min (desc_len, ENTITYLEN));
	  *leasetimep = mp->leasetime;
	  return i;
	}
    }
  return -1;
}

static int
UpnpProxy_upnp_get_redirection_infos 
(
 int eport,			/* IN */
 char protocol[],		/* IN */
 int *iportp,			/* IN */
 char int_ip[],			/* OUT */
 int int_ip_len,
 char desc[],			/* OUT */
 int desc_len, 
 int *leasetimep		/* OUT */
 )
{
  int rc;
#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  rc = AUX_upnp_get_redirection_infos
    (eport, protocol, iportp, int_ip, int_ip_len, desc, desc_len, leasetimep);

#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

  return rc;
}


/*
 * Non MT safe function. Protect this function with mutex before call.
 */
static int
AUX_upnp_get_redirection_infos_by_index 
(
 int index,			/* IN */
 int *eportp,			/* OUT */
 char *protocol,		/* OUT */
 int *iportp,			/* OUT */
 char iaddr[],			/* OUT */
 int iaddrlen,
 char desc[],			/* OUT */
 int desclen, 
 int *leasep			/* OUT */
 )
{
  int i = index;
  int j;

  MYREDIRECT *mp;
  
  if(verbose > 2)
    UpnpProxy_SampleUtil_Print ("upnp_get_redirection_info by index called: index = %d\n",
		    index);

  if (i < 0 && i >= RULESMAX)
    return -1;

  upnp_get_portmapping_number_of_entries ();	/* RENUMBER externally visible indices */

  for (j = 0; j < RULESMAX; j++)
    if (redirecttable[j].used &&
	redirecttable[j].externally_visible_index == index)
      break;

  if (j >= RULESMAX)
    return -1;

  mp = &redirecttable[j];

  *eportp = mp->externalPort;
  *iportp = mp->internalPort;
  strncpy (iaddr, mp->internalIp, iaddrlen);
  strncpy (protocol, mp->protocol, 4);
  strncpy (desc, mp->desc, desclen);
  *leasep = mp->leasetime;
  return 0;

}


static int
UpnpProxy_upnp_get_redirection_infos_by_index 
   (
    int index,			/* IN */
    int *eportp,		/* OUT */
    char *protocol,		/* OUT */
    int *iportp,		/* OUT */
    char iaddr[],		/* OUT */
    int iaddrlen,
    char desc[], 		/* OUT */
    int desclen, 
    int *leasep			/* OUT */
    )
{
  int rc;

#if 0
  ithread_mutex_lock (&NatRulesMutex);
#endif

  rc = AUX_upnp_get_redirection_infos_by_index
    (index, eportp, protocol, iportp, iaddr, iaddrlen, desc, desclen, leasep);

#if 0
  ithread_mutex_unlock (&NatRulesMutex);
#endif

  return rc;
}

