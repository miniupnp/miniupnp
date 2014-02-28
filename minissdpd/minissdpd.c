/* $Id: minissdpd.c,v 1.37 2014/02/28 18:39:11 nanard Exp $ */
/* MiniUPnP project
 * (c) 2007-2014 Thomas Bernard
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <sys/queue.h>
/* for chmod : */
#include <sys/stat.h>
/* unix sockets */
#include <sys/un.h>
/* for getpwnam() and getgrnam() */
#include <pwd.h>
#include <grp.h>

#include "upnputils.h"
#include "openssdpsocket.h"
#include "daemonize.h"
#include "codelength.h"
#include "ifacewatch.h"

/* current request management stucture */
struct reqelem {
	int socket;
	LIST_ENTRY(reqelem) entries;
};

/* divice data structures */
struct header {
	const char * p; /* string pointer */
	int l;          /* string length */
};

#define HEADER_NT	0
#define HEADER_USN	1
#define HEADER_LOCATION	2

struct device {
	struct device * next;
	time_t t;                 /* validity time */
	struct header headers[3]; /* NT, USN and LOCATION headers */
	char data[];
};

#define NTS_SSDP_ALIVE	1
#define NTS_SSDP_BYEBYE	2
#define NTS_SSDP_UPDATE	3

/* discovered device list kept in memory */
struct device * devlist = 0;

/* bootid and configid */
unsigned int upnp_bootid = 1;
unsigned int upnp_configid = 1337;

static const char *
nts_to_str(int nts)
{
	switch(nts)
	{
	case NTS_SSDP_ALIVE:
		return "ssdp:alive";
	case NTS_SSDP_BYEBYE:
		return "ssdp:byebye";
	case NTS_SSDP_UPDATE:
		return "ssdp:update";
	}
	return "unknown";
}

/* updateDevice() :
 * adds or updates the device to the list.
 * return value :
 *   0 : the device was updated (or nothing done)
 *   1 : the device was new    */
static int
updateDevice(const struct header * headers, time_t t)
{
	struct device ** pp = &devlist;
	struct device * p = *pp;	/* = devlist; */
	while(p)
	{
		if(  p->headers[HEADER_NT].l == headers[HEADER_NT].l
		  && (0==memcmp(p->headers[HEADER_NT].p, headers[HEADER_NT].p, headers[HEADER_NT].l))
		  && p->headers[HEADER_USN].l == headers[HEADER_USN].l
		  && (0==memcmp(p->headers[HEADER_USN].p, headers[HEADER_USN].p, headers[HEADER_USN].l)) )
		{
			/*printf("found! %d\n", (int)(t - p->t));*/
			syslog(LOG_DEBUG, "device updated : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
			p->t = t;
			/* update Location ! */
			if(headers[HEADER_LOCATION].l > p->headers[HEADER_LOCATION].l)
			{
				p = realloc(p, sizeof(struct device)
		           + headers[0].l+headers[1].l+headers[2].l );
				if(!p)	/* allocation error */
				{
					syslog(LOG_ERR, "updateDevice() : memory allocation error");
					return 0;
				}
				*pp = p;
			}
			memcpy(p->data + p->headers[0].l + p->headers[1].l,
			       headers[2].p, headers[2].l);
			return 0;
		}
		pp = &p->next;
		p = *pp;	/* p = p->next; */
	}
	syslog(LOG_INFO, "new device discovered : %.*s",
	       headers[HEADER_USN].l, headers[HEADER_USN].p);
	/* add */
	{
		char * pc;
		int i;
		p = malloc(  sizeof(struct device)
		           + headers[0].l+headers[1].l+headers[2].l );
		if(!p) {
			syslog(LOG_ERR, "updateDevice(): cannot allocate memory");
			return -1;
		}
		p->next = devlist;
		p->t = t;
		pc = p->data;
		for(i = 0; i < 3; i++)
		{
			p->headers[i].p = pc;
			p->headers[i].l = headers[i].l;
			memcpy(pc, headers[i].p, headers[i].l);
			pc += headers[i].l;
		}
		devlist = p;
	}
	return 1;
}

/* removeDevice() :
 * remove a device from the list
 * return value :
 *    0 : no device removed
 *   -1 : device removed */
static int
removeDevice(const struct header * headers)
{
	struct device ** pp = &devlist;
	struct device * p = *pp;	/* = devlist */
	while(p)
	{
		if(  p->headers[HEADER_NT].l == headers[HEADER_NT].l
		  && (0==memcmp(p->headers[HEADER_NT].p, headers[HEADER_NT].p, headers[HEADER_NT].l))
		  && p->headers[HEADER_USN].l == headers[HEADER_USN].l
		  && (0==memcmp(p->headers[HEADER_USN].p, headers[HEADER_USN].p, headers[HEADER_USN].l)) )
		{
			syslog(LOG_INFO, "remove device : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
			*pp = p->next;
			free(p);
			return -1;
		}
		pp = &p->next;
		p = *pp;	/* p = p->next; */
	}
	syslog(LOG_WARNING, "device not found for removing : %.*s", headers[HEADER_USN].l, headers[HEADER_USN].p);
	return 0;
}

/* SendSSDPMSEARCHResponse() :
 * build and send response to M-SEARCH SSDP packets. */
static void
SendSSDPMSEARCHResponse(int s, const struct sockaddr * sockname,
                        const char * st, const char * usn,
                        const char * server, const char * location)
{
	int l, n;
	char buf[512];
	socklen_t sockname_len;
	/*
	 * follow guideline from document "UPnP Device Architecture 1.0"
	 * uppercase is recommended.
	 * DATE: is recommended
	 * SERVER: OS/ver UPnP/1.0 miniupnpd/1.0
	 * - check what to put in the 'Cache-Control' header
	 *
	 * have a look at the document "UPnP Device Architecture v1.1 */
	l = snprintf(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n"
		"CACHE-CONTROL: max-age=120\r\n"
		/*"DATE: ...\r\n"*/
		"ST: %s\r\n"
		"USN: %s\r\n"
		"EXT:\r\n"
		"SERVER: %s\r\n"
		"LOCATION: %s\r\n"
		"OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n" /* UDA v1.1 */
		"01-NLS: %u\r\n" /* same as BOOTID. UDA v1.1 */
		"BOOTID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
		"CONFIGID.UPNP.ORG: %u\r\n" /* UDA v1.1 */
		"\r\n",
		st, usn,
		server, location,
		upnp_bootid, upnp_bootid, upnp_configid);
#ifdef ENABLE_IPV6
	sockname_len = (sockname->sa_family == PF_INET6)
	             ? sizeof(struct sockaddr_in6)
	             : sizeof(struct sockaddr_in);
#else
	sockname_len = sizeof(struct sockaddr_in);
#endif
	n = sendto(s, buf, l, 0,
	           sockname, sockname_len );
	if(n < 0) {
		/* XXX handle EINTR, EAGAIN, EWOULDBLOCK */
		syslog(LOG_ERR, "sendto(udp): %m");
	}
}

/* Services stored for answering to M-SEARCH */
struct service {
	char * st;	/* Service type */
	char * usn;	/* Unique identifier */
	char * server;	/* Server string */
	char * location;	/* URL */
	LIST_ENTRY(service) entries;
};
LIST_HEAD(servicehead, service) servicelisthead;

/* Process M-SEARCH requests */
static void
processMSEARCH(int s, const char * st, int st_len,
               const struct sockaddr * addr)
{
	struct service * serv;
#ifdef ENABLE_IPV6
	char buf[64];
#endif

	if(!st || st_len==0)
		return;
#ifdef ENABLE_IPV6
	sockaddr_to_string(addr, buf, sizeof(buf));
	syslog(LOG_INFO, "SSDP M-SEARCH from %s ST:%.*s",
	       buf, st_len, st);
#else
	syslog(LOG_INFO, "SSDP M-SEARCH from %s:%d ST: %.*s",
	       inet_ntoa(((const struct sockaddr_in *)addr)->sin_addr),
	       ntohs(((const struct sockaddr_in *)addr)->sin_port),
	       st_len, st);
#endif
	if(st_len==8 && (0==memcmp(st, "ssdp:all", 8))) {
		/* send a response for all services */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			SendSSDPMSEARCHResponse(s, addr,
			                        serv->st, serv->usn,
			                        serv->server, serv->location);
		}
	} else if(st_len > 5 && (0==memcmp(st, "uuid:", 5))) {
		/* find a matching UUID value */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strncmp(serv->usn, st, st_len)) {
				SendSSDPMSEARCHResponse(s, addr,
				                        serv->st, serv->usn,
				                        serv->server, serv->location);
			}
		}
	} else {
		/* find matching services */
		/* remove version at the end of the ST string */
		if(st[st_len-2]==':' && isdigit(st[st_len-1]))
			st_len -= 2;
		/* answer for each matching service */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strncmp(serv->st, st, st_len)) {
				SendSSDPMSEARCHResponse(s, addr,
				                        serv->st, serv->usn,
				                        serv->server, serv->location);
			}
		}
	}
}

/**
 * helper function.
 * reject any non ASCII or non printable character.
 */
static int
containsForbiddenChars(const unsigned char * p, int len)
{
	while(len > 0) {
		if(*p < ' ' || *p >= '\x7f')
			return 1;
		p++;
		len--;
	}
	return 0;
}

#define METHOD_MSEARCH 1
#define METHOD_NOTIFY 2

/* ParseSSDPPacket() :
 * parse a received SSDP Packet and call
 * updateDevice() or removeDevice() as needed
 * return value :
 *    -1 : a device was removed
 *     0 : no device removed nor added
 *     1 : a device was added.  */
static int
ParseSSDPPacket(int s, const char * p, ssize_t n,
                const struct sockaddr * addr)
{
	const char * linestart;
	const char * lineend;
	const char * nameend;
	const char * valuestart;
	struct header headers[3];
	int i, r = 0;
	int methodlen;
	int nts = -1;
	int method = -1;
	unsigned int lifetime = 180;	/* 3 minutes by default */
	const char * st = NULL;
	int st_len = 0;

	memset(headers, 0, sizeof(headers));
	for(methodlen = 0;
	    methodlen < n && (isalpha(p[methodlen]) || p[methodlen]=='-');
		methodlen++);
	if(methodlen==8 && 0==memcmp(p, "M-SEARCH", 8))
		method = METHOD_MSEARCH;
	else if(methodlen==6 && 0==memcmp(p, "NOTIFY", 6))
		method = METHOD_NOTIFY;
	else if(methodlen==4 && 0==memcmp(p, "HTTP", 4)) {
		/* answer to a M-SEARCH => process it as a NOTIFY
		 * with NTS: ssdp:alive */
		method = METHOD_NOTIFY;
		nts = NTS_SSDP_ALIVE;
	}
	linestart = p;
	while(linestart < p + n - 2) {
		/* start parsing the line : detect line end */
		lineend = linestart;
		while(lineend < p + n && *lineend != '\n' && *lineend != '\r')
			lineend++;
		/*printf("line: '%.*s'\n", lineend - linestart, linestart);*/
		/* detect name end : ':' character */
		nameend = linestart;
		while(nameend < lineend && *nameend != ':')
			nameend++;
		/* detect value */
		if(nameend < lineend)
			valuestart = nameend + 1;
		else
			valuestart = nameend;
		/* trim spaces */
		while(valuestart < lineend && isspace(*valuestart))
			valuestart++;
		/* suppress leading " if needed */
		if(valuestart < lineend && *valuestart=='\"')
			valuestart++;
		if(nameend > linestart && valuestart < lineend) {
			int l = nameend - linestart;	/* header name length */
			int m = lineend - valuestart;	/* header value length */
			/* suppress tailing spaces */
			while(m>0 && isspace(valuestart[m-1]))
				m--;
			/* suppress tailing ' if needed */
			if(m>0 && valuestart[m-1] == '\"')
				m--;
			i = -1;
			/*printf("--%.*s: (%d)%.*s--\n", l, linestart,
			                           m, m, valuestart);*/
			if(l==2 && 0==strncasecmp(linestart, "nt", 2))
				i = HEADER_NT;
			else if(l==3 && 0==strncasecmp(linestart, "usn", 3))
				i = HEADER_USN;
			else if(l==3 && 0==strncasecmp(linestart, "nts", 3)) {
				if(m==10 && 0==strncasecmp(valuestart, "ssdp:alive", 10))
					nts = NTS_SSDP_ALIVE;
				else if(m==11 && 0==strncasecmp(valuestart, "ssdp:byebye", 11))
					nts = NTS_SSDP_BYEBYE;
				else if(m==11 && 0==strncasecmp(valuestart, "ssdp:update", 11))
					nts = NTS_SSDP_UPDATE;
			}
			else if(l==8 && 0==strncasecmp(linestart, "location", 8))
				i = HEADER_LOCATION;
			else if(l==13 && 0==strncasecmp(linestart, "cache-control", 13)) {
				/* parse "name1=value1, name_alone, name2=value2" string */
				const char * name = valuestart;	/* name */
				const char * val;				/* value */
				int rem = m;	/* remaining bytes to process */
				while(rem > 0) {
					val = name;
					while(val < name + rem && *val != '=' && *val != ',')
						val++;
					if(val >= name + rem)
						break;
					if(*val == '=') {
						while(val < name + rem && (*val == '=' || isspace(*val)))
							val++;
						if(val >= name + rem)
							break;
						if(0==strncasecmp(name, "max-age", 7))
							lifetime = (unsigned int)strtoul(val, 0, 0);
						/* move to the next name=value pair */
						while(rem > 0 && *name != ',') {
							rem--;
							name++;
						}
						/* skip spaces */
						while(rem > 0 && (*name == ',' || isspace(*name))) {
							rem--;
							name++;
						}
					} else {
						rem -= (val - name);
						name = val;
						while(rem > 0 && (*name == ',' || isspace(*name))) {
							rem--;
							name++;
						}
					}
				}
				/*syslog(LOG_DEBUG, "**%.*s**%u", m, valuestart, lifetime);*/
			} else if(l==2 && 0==strncasecmp(linestart, "st", 2)) {
				st = valuestart;
				st_len = m;
				if(method == METHOD_NOTIFY)
					i = HEADER_NT;	/* it was a M-SEARCH response */
			}
			if(i>=0) {
				headers[i].p = valuestart;
				headers[i].l = m;
			}
		}
		linestart = lineend;
		while((*linestart == '\n' || *linestart == '\r') && linestart < p + n)
			linestart++;
	}
#if 0
	printf("NTS=%d\n", nts);
	for(i=0; i<3; i++) {
		if(headers[i].p)
			printf("%d-'%.*s'\n", i, headers[i].l, headers[i].p);
	}
#endif
	syslog(LOG_DEBUG,"SSDP request: '%.*s' (%d) %s %s=%.*s",
	       methodlen, p, method, nts_to_str(nts),
	       (method==METHOD_NOTIFY)?"nt":"st",
	       (method==METHOD_NOTIFY)?headers[HEADER_NT].l:st_len,
	       (method==METHOD_NOTIFY)?headers[HEADER_NT].p:st);
	switch(method) {
	case METHOD_NOTIFY:
		if(headers[HEADER_NT].p && headers[HEADER_USN].p && headers[HEADER_LOCATION].p) {
			if(nts==NTS_SSDP_ALIVE) {
				r = updateDevice(headers, time(NULL) + lifetime);
			}
			else if(nts==NTS_SSDP_BYEBYE) {
				r = removeDevice(headers);
			}
		}
		break;
	case METHOD_MSEARCH:
		processMSEARCH(s, st, st_len, addr);
		break;
	default:
		syslog(LOG_WARNING, "method %.*s, don't know what to do", methodlen, p);
	}
	return r;
}

/* OpenUnixSocket()
 * open the unix socket and call bind() and listen()
 * return -1 in case of error */
static int
OpenUnixSocket(const char * path)
{
	struct sockaddr_un addr;
	int s;
	int rv;
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s < 0)
	{
		syslog(LOG_ERR, "socket(AF_UNIX): %m");
		return -1;
	}
	/* unlink the socket pseudo file before binding */
	rv = unlink(path);
	if(rv < 0 && errno != ENOENT)
	{
		syslog(LOG_ERR, "unlink(unixsocket, \"%s\"): %m", path);
		close(s);
		return -1;
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path));
	if(bind(s, (struct sockaddr *)&addr,
	           sizeof(struct sockaddr_un)) < 0)
	{
		syslog(LOG_ERR, "bind(unixsocket, \"%s\"): %m", path);
		close(s);
		return -1;
	}
	else if(listen(s, 5) < 0)
	{
		syslog(LOG_ERR, "listen(unixsocket): %m");
		close(s);
		return -1;
	}
	/* Change rights so everyone can communicate with us */
	if(chmod(path, 0666) < 0)
	{
		syslog(LOG_WARNING, "chmod(\"%s\"): %m", path);
	}
	return s;
}

/* processRequest() :
 * process the request coming from a unix socket */
void processRequest(struct reqelem * req)
{
	ssize_t n;
	unsigned int l, m;
	unsigned char buf[2048];
	const unsigned char * p;
	int type;
	struct device * d = devlist;
	unsigned char rbuf[4096];
	unsigned char * rp = rbuf+1;
	unsigned char nrep = 0;
	time_t t;
	struct service * newserv = NULL;
	struct service * serv;

	n = read(req->socket, buf, sizeof(buf));
	if(n<0) {
		if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;	/* try again later */
		syslog(LOG_ERR, "(s=%d) processRequest(): read(): %m", req->socket);
		goto error;
	}
	if(n==0) {
		syslog(LOG_INFO, "(s=%d) request connection closed", req->socket);
		goto error;
	}
	t = time(NULL);
	type = buf[0];
	p = buf + 1;
	DECODELENGTH_CHECKLIMIT(l, p, buf + n);
	if(p+l > buf+n) {
		syslog(LOG_WARNING, "bad request (length encoding)");
		goto error;
	}
	if(l == 0 && type != 3) {
		syslog(LOG_WARNING, "bad request (length=0)");
		goto error;
	}
	syslog(LOG_INFO, "(s=%d) request type=%d str='%.*s'",
	       req->socket, type, l, p);
	switch(type) {
	case 1:	/* request by type */
	case 2:	/* request by USN (unique id) */
	case 3:	/* everything */
		while(d && (nrep < 255)) {
			if(d->t < t) {
				syslog(LOG_INFO, "outdated device");
			} else {
				/* test if we can put more responses in the buffer */
				if(d->headers[HEADER_LOCATION].l + d->headers[HEADER_NT].l
				  + d->headers[HEADER_USN].l + 6
				  + (rp - rbuf) >= (int)sizeof(rbuf))
					break;
				if( (type==1 && 0==memcmp(d->headers[HEADER_NT].p, p, l))
				  ||(type==2 && 0==memcmp(d->headers[HEADER_USN].p, p, l))
				  ||(type==3) ) {
					/* response :
					 * 1 - Location
					 * 2 - NT (device/service type)
					 * 3 - usn */
					m = d->headers[HEADER_LOCATION].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_LOCATION].p, d->headers[HEADER_LOCATION].l);
					rp += d->headers[HEADER_LOCATION].l;
					m = d->headers[HEADER_NT].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_NT].p, d->headers[HEADER_NT].l);
					rp += d->headers[HEADER_NT].l;
					m = d->headers[HEADER_USN].l;
					CODELENGTH(m, rp);
					memcpy(rp, d->headers[HEADER_USN].p, d->headers[HEADER_USN].l);
					rp += d->headers[HEADER_USN].l;
					nrep++;
				}
			}
			d = d->next;
		}
		/* Also look in service list */
		for(serv = servicelisthead.lh_first;
		    serv && (nrep < 255);
		    serv = serv->entries.le_next) {
			/* test if we can put more responses in the buffer */
			if(strlen(serv->location) + strlen(serv->st)
			  + strlen(serv->usn) + 6 + (rp - rbuf) >= sizeof(rbuf))
			  	break;
			if( (type==1 && 0==strncmp(serv->st, (const char *)p, l))
			  ||(type==2 && 0==strncmp(serv->usn, (const char *)p, l))
			  ||(type==3) ) {
				/* response :
				 * 1 - Location
				 * 2 - NT (device/service type)
				 * 3 - usn */
				m = strlen(serv->location);
				CODELENGTH(m, rp);
				memcpy(rp, serv->location, m);
				rp += m;
				m = strlen(serv->st);
				CODELENGTH(m, rp);
				memcpy(rp, serv->st, m);
				rp += m;
				m = strlen(serv->usn);
				CODELENGTH(m, rp);
				memcpy(rp, serv->usn, m);
				rp += m;
				nrep++;
			}
		}
		rbuf[0] = nrep;
		syslog(LOG_DEBUG, "(s=%d) response : %d device%s",
		       req->socket, nrep, (nrep > 1) ? "s" : "");
		if(write(req->socket, rbuf, rp - rbuf) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
		break;
	case 4:	/* submit service */
		newserv = malloc(sizeof(struct service));
		if(!newserv) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (st contains forbidden chars)");
			goto error;
		}
		newserv->st = malloc(l + 1);
		if(!newserv->st) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->st, p, l);
		newserv->st[l] = '\0';
		p += l;
		if(p >= buf + n) {
			syslog(LOG_WARNING, "bad request (missing usn)");
			goto error;
		}
		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
			syslog(LOG_WARNING, "bad request (length encoding)");
			goto error;
		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (usn contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "usn='%.*s'", l, p);
		newserv->usn = malloc(l + 1);
		if(!newserv->usn) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->usn, p, l);
		newserv->usn[l] = '\0';
		p += l;
		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
			syslog(LOG_WARNING, "bad request (length encoding)");
			goto error;
		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (server contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "server='%.*s'", l, p);
		newserv->server = malloc(l + 1);
		if(!newserv->server) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->server, p, l);
		newserv->server[l] = '\0';
		p += l;
		DECODELENGTH_CHECKLIMIT(l, p, buf + n);
		if(p+l > buf+n) {
			syslog(LOG_WARNING, "bad request (length encoding)");
			goto error;
		}
		if(containsForbiddenChars(p, l)) {
			syslog(LOG_ERR, "bad request (location contains forbidden chars)");
			goto error;
		}
		syslog(LOG_INFO, "location='%.*s'", l, p);
		newserv->location = malloc(l + 1);
		if(!newserv->location) {
			syslog(LOG_ERR, "cannot allocate memory");
			goto error;
		}
		memcpy(newserv->location, p, l);
		newserv->location[l] = '\0';
		/* look in service list for duplicate */
		for(serv = servicelisthead.lh_first;
		    serv;
		    serv = serv->entries.le_next) {
			if(0 == strcmp(newserv->usn, serv->usn)
			  && 0 == strcmp(newserv->st, serv->st)) {
				syslog(LOG_INFO, "Service allready in the list. Updating...");
				free(newserv->st);
				free(newserv->usn);
				free(serv->server);
				serv->server = newserv->server;
				free(serv->location);
				serv->location = newserv->location;
				free(newserv);
				newserv = NULL;
				return;
			}
		}
		/* Inserting new service */
		LIST_INSERT_HEAD(&servicelisthead, newserv, entries);
		newserv = NULL;
		/*rbuf[0] = '\0';
		if(write(req->socket, rbuf, 1) < 0)
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
		*/
		break;
	default:
		syslog(LOG_WARNING, "Unknown request type %d", type);
		rbuf[0] = '\0';
		if(write(req->socket, rbuf, 1) < 0) {
			syslog(LOG_ERR, "(s=%d) write: %m", req->socket);
			goto error;
		}
	}
	return;
error:
	if(newserv) {
		free(newserv->st);
		free(newserv->usn);
		free(newserv->server);
		free(newserv->location);
		free(newserv);
		newserv = NULL;
	}
	close(req->socket);
	req->socket = -1;
	return;
}

static volatile sig_atomic_t quitting = 0;
/* SIGTERM signal handler */
static void
sigterm(int sig)
{
	(void)sig;
	/*int save_errno = errno;*/
	/*signal(sig, SIG_IGN);*/
#if 0
	/* calling syslog() is forbidden in a signal handler according to
	 * signal(3) */
	syslog(LOG_NOTICE, "received signal %d, good-bye", sig);
#endif
	quitting = 1;
	/*errno = save_errno;*/
}

#define PORT 1900
#define XSTR(s) STR(s)
#define STR(s) #s
#define UPNP_MCAST_ADDR "239.255.255.250"
/* for IPv6 */
#define UPNP_MCAST_LL_ADDR "FF02::C" /* link-local */
#define UPNP_MCAST_SL_ADDR "FF05::C" /* site-local */

/* send the M-SEARCH request for all devices */
void ssdpDiscoverAll(int s, int ipv6)
{
	static const char MSearchMsgFmt[] =
	"M-SEARCH * HTTP/1.1\r\n"
	"HOST: %s:" XSTR(PORT) "\r\n"
	"ST: ssdp:all\r\n"
	"MAN: \"ssdp:discover\"\r\n"
	"MX: %u\r\n"
	"\r\n";
	char bufr[512];
	int n;
	int mx = 3;
	int linklocal = 1;
	struct sockaddr_storage sockudp_w;

	{
		n = snprintf(bufr, sizeof(bufr),
		             MSearchMsgFmt,
		             ipv6 ?
		             (linklocal ? "[" UPNP_MCAST_LL_ADDR "]" :  "[" UPNP_MCAST_SL_ADDR "]")
		             : UPNP_MCAST_ADDR, mx);
		memset(&sockudp_w, 0, sizeof(struct sockaddr_storage));
		if(ipv6) {
			struct sockaddr_in6 * p = (struct sockaddr_in6 *)&sockudp_w;
			p->sin6_family = AF_INET6;
			p->sin6_port = htons(PORT);
			inet_pton(AF_INET6,
			          linklocal ? UPNP_MCAST_LL_ADDR : UPNP_MCAST_SL_ADDR,
			          &(p->sin6_addr));
		} else {
			struct sockaddr_in * p = (struct sockaddr_in *)&sockudp_w;
			p->sin_family = AF_INET;
			p->sin_port = htons(PORT);
			p->sin_addr.s_addr = inet_addr(UPNP_MCAST_ADDR);
		}

		n = sendto(s, bufr, n, 0, (const struct sockaddr *)&sockudp_w,
		           ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
		if (n < 0) {
			/* XXX : EINTR EWOULDBLOCK EAGAIN */
			syslog(LOG_ERR, "sendto: %m");
		}
	}
}

/* main(): program entry point */
int main(int argc, char * * argv)
{
	int ret = 0;
	int pid;
	struct sigaction sa;
	char buf[1500];
	ssize_t n;
	int s_ssdp = -1;	/* udp socket receiving ssdp packets */
#ifdef ENABLE_IPV6
	int s_ssdp6 = -1;	/* udp socket receiving ssdp packets IPv6*/
#else
#define s_ssdp6 (-1)
#endif
	int s_unix = -1;	/* unix socket communicating with clients */
	int s_ifacewatch = -1;	/* socket to receive Route / network interface config changes */
	int s;
	LIST_HEAD(reqstructhead, reqelem) reqlisthead;
	struct reqelem * req;
	struct reqelem * reqnext;
	fd_set readfds;
	const char * if_addr[MAX_IF_ADDR];
	int n_if_addr = 0;
	int i;
	const char * sockpath = "/var/run/minissdpd.sock";
	const char * pidfilename = "/var/run/minissdpd.pid";
	int debug_flag = 0;
	int ipv6 = 0;
	int deltadev = 0;
	struct sockaddr_in sendername;
	socklen_t sendername_len;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 sendername6;
	socklen_t sendername6_len;
#endif

	LIST_INIT(&reqlisthead);
	LIST_INIT(&servicelisthead);
	/* process command line */
	for(i=1; i<argc; i++)
	{
		if(0==strcmp(argv[i], "-i")) {
			if(n_if_addr < MAX_IF_ADDR)
				if_addr[n_if_addr++] = argv[++i];
			else
				syslog(LOG_WARNING, "Max number of interface address set to %d, "
				       "ignoring %s", MAX_IF_ADDR, argv[++i]);
		} else if(0==strcmp(argv[i], "-d"))
			debug_flag = 1;
		else if(0==strcmp(argv[i], "-s"))
			sockpath = argv[++i];
		else if(0==strcmp(argv[i], "-p"))
			pidfilename = argv[++i];
#ifdef ENABLE_IPV6
		else if(0==strcmp(argv[i], "-6"))
			ipv6 = 1;
#endif
	}
	if(n_if_addr < 1)
	{
		fprintf(stderr,
		        "Usage: %s [-d] [-6] [-s socket] [-p pidfile] "
				"-i <interface> [-i <interface2>] ...\n",
		        argv[0]);
		fprintf(stderr,
		        "\n  <interface> is either an IPv4 address such as 192.168.1.42, or an\ninterface name such as eth0.\n");
		fprintf(stderr,
		        "\n  By default, socket will be open as %s\n"
		        "and pid written to file %s\n",
		        sockpath, pidfilename);
		return 1;
	}

	/* open log */
	openlog("minissdpd",
	        LOG_CONS|LOG_PID|(debug_flag?LOG_PERROR:0),
			LOG_MINISSDPD);
	if(!debug_flag) /* speed things up and ignore LOG_INFO and LOG_DEBUG */
		setlogmask(LOG_UPTO(LOG_NOTICE));

	if(checkforrunning(pidfilename) < 0)
	{
		syslog(LOG_ERR, "MiniSSDPd is already running. EXITING");
		return 1;
	}

	/* set signal handlers */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sigterm;
	if(sigaction(SIGTERM, &sa, NULL))
	{
		syslog(LOG_ERR, "Failed to set SIGTERM handler. EXITING");
		ret = 1;
		goto quit;
	}
	if(sigaction(SIGINT, &sa, NULL))
	{
		syslog(LOG_ERR, "Failed to set SIGINT handler. EXITING");
		ret = 1;
		goto quit;
	}
	/* open route/interface config changes socket */
	s_ifacewatch = OpenAndConfInterfaceWatchSocket();
	/* open UDP socket(s) for receiving SSDP packets */
	s_ssdp = OpenAndConfSSDPReceiveSocket(n_if_addr, if_addr, 0);
	if(s_ssdp < 0)
	{
		syslog(LOG_ERR, "Cannot open socket for receiving SSDP messages, exiting");
		ret = 1;
		goto quit;
	}
#ifdef ENABLE_IPV6
	if(ipv6) {
		s_ssdp6 = OpenAndConfSSDPReceiveSocket(n_if_addr, if_addr, 1);
		if(s_ssdp6 < 0)
		{
			syslog(LOG_ERR, "Cannot open socket for receiving SSDP messages (IPv6), exiting");
			ret = 1;
			goto quit;
		}
	}
#endif
	/* Open Unix socket to communicate with other programs on
	 * the same machine */
	s_unix = OpenUnixSocket(sockpath);
	if(s_unix < 0)
	{
		syslog(LOG_ERR, "Cannot open unix socket for communicating with clients. Exiting");
		ret = 1;
		goto quit;
	}

	/* drop privileges */
#if 0
	/* if we drop privileges, how to unlink(/var/run/minissdpd.sock) ? */
	if(getuid() == 0) {
		struct passwd * user;
		struct group * group;
		user = getpwnam("nobody");
		if(!user) {
			syslog(LOG_ERR, "getpwnam(\"%s\") : %m", "nobody");
			ret = 1;
			goto quit;
		}
		group = getgrnam("nogroup");
		if(!group) {
			syslog(LOG_ERR, "getgrnam(\"%s\") : %m", "nogroup");
			ret = 1;
			goto quit;
		}
		if(setgid(group->gr_gid) < 0) {
			syslog(LOG_ERR, "setgit(%d) : %m", group->gr_gid);
			ret = 1;
			goto quit;
		}
		if(setuid(user->pw_uid) < 0) {
			syslog(LOG_ERR, "setuid(%d) : %m", user->pw_uid);
			ret = 1;
			goto quit;
		}
	}
#endif

	/* daemonize or in any case get pid ! */
	if(debug_flag)
		pid = getpid();
	else {
#ifdef USE_DAEMON
		if(daemon(0, 0) < 0)
			perror("daemon()");
		pid = getpid();
#else
		pid = daemonize();
#endif
	}

	writepidfile(pidfilename, pid);

	/* send M-SEARCH ssdp:all Requests */
	ssdpDiscoverAll(s_ssdp, 0);
	if(s_ssdp6 >= 0)
		ssdpDiscoverAll(s_ssdp6, 1);

	/* Main loop */
	while(!quitting)
	{
		/* fill readfds fd_set */
		FD_ZERO(&readfds);
		if(s_ssdp >= 0) {
			FD_SET(s_ssdp, &readfds);
		}
#ifdef ENABLE_IPV6
		if(s_ssdp6 >= 0) {
			FD_SET(s_ssdp6, &readfds);
		}
#endif
		if(s_ifacewatch >= 0) {
			FD_SET(s_ifacewatch, &readfds);
		}
		FD_SET(s_unix, &readfds);
		for(req = reqlisthead.lh_first; req; req = req->entries.le_next)
		{
			if(req->socket >= 0)
				FD_SET(req->socket, &readfds);
		}
		/* select call */
		if(select(FD_SETSIZE, &readfds, 0, 0, 0) < 0)
		{
			if(errno != EINTR)
			{
				syslog(LOG_ERR, "select: %m");
				break;	/* quit */
			}
			continue;	/* try again */
		}
#ifdef ENABLE_IPV6
		if((s_ssdp6 >= 0) && FD_ISSET(s_ssdp6, &readfds))
		{
			sendername6_len = sizeof(struct sockaddr_in6);
			n = recvfrom(s_ssdp6, buf, sizeof(buf), 0,
			             (struct sockaddr *)&sendername6, &sendername6_len);
			if(n<0)
			{
				 /* EAGAIN, EWOULDBLOCK, EINTR : silently ignore (try again next time)
				  * other errors : log to LOG_ERR */
				if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
					syslog(LOG_ERR, "recvfrom: %m");
			}
			else
			{
				/* Parse and process the packet received */
				/*printf("%.*s", n, buf);*/
				i = ParseSSDPPacket(s_ssdp6, buf, n,
				                    (struct sockaddr *)&sendername6);
				syslog(LOG_DEBUG, "** i=%d deltadev=%d **", i, deltadev);
				if(i==0 || (i*deltadev < 0))
				{
					if(deltadev > 0)
						syslog(LOG_NOTICE, "%d new devices added", deltadev);
					else if(deltadev < 0)
						syslog(LOG_NOTICE, "%d devices removed (good-bye!)", -deltadev);
					deltadev = i;
				}
				else if((i*deltadev) >= 0)
				{
					deltadev += i;
				}
			}
		}
#endif
		if(FD_ISSET(s_ssdp, &readfds))
		{
			sendername_len = sizeof(struct sockaddr_in);
			n = recvfrom(s_ssdp, buf, sizeof(buf), 0,
			             (struct sockaddr *)&sendername, &sendername_len);
			if(n<0)
			{
				 /* EAGAIN, EWOULDBLOCK, EINTR : silently ignore (try again next time)
				  * other errors : log to LOG_ERR */
				if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
					syslog(LOG_ERR, "recvfrom: %m");
			}
			else
			{
				/* Parse and process the packet received */
				/*printf("%.*s", n, buf);*/
				i = ParseSSDPPacket(s_ssdp, buf, n,
				                    (struct sockaddr *)&sendername);
				syslog(LOG_DEBUG, "** i=%d deltadev=%d **", i, deltadev);
				if(i==0 || (i*deltadev < 0))
				{
					if(deltadev > 0)
						syslog(LOG_NOTICE, "%d new devices added", deltadev);
					else if(deltadev < 0)
						syslog(LOG_NOTICE, "%d devices removed (good-bye!)", -deltadev);
					deltadev = i;
				}
				else if((i*deltadev) >= 0)
				{
					deltadev += i;
				}
			}
		}
		/* processing unix socket requests */
		for(req = reqlisthead.lh_first; req;)
		{
			reqnext = req->entries.le_next;
			if((req->socket >= 0) && FD_ISSET(req->socket, &readfds))
			{
				processRequest(req);
			}
			if(req->socket < 0)
			{
				LIST_REMOVE(req, entries);
				free(req);
			}
			req = reqnext;
		}
		/* processing new requests */
		if(FD_ISSET(s_unix, &readfds))
		{
			struct reqelem * tmp;
			s = accept(s_unix, NULL, NULL);
			if(s<0)
			{
				syslog(LOG_ERR, "accept(s_unix): %m");
			}
			else
			{
				syslog(LOG_INFO, "(s=%d) new request connection", s);
				if(!set_non_blocking(s))
					syslog(LOG_WARNING, "Failed to set new socket non blocking : %m");
				tmp = malloc(sizeof(struct reqelem));
				if(!tmp)
				{
					syslog(LOG_ERR, "cannot allocate memory for request");
					close(s);
				}
				else
				{
					tmp->socket = s;
					LIST_INSERT_HEAD(&reqlisthead, tmp, entries);
				}
			}
		}
		/* processing route/network interface config changes */
		if((s_ifacewatch >= 0) && FD_ISSET(s_ifacewatch, &readfds)) {
			ProcessInterfaceWatch(s_ifacewatch, s_ssdp, s_ssdp6, n_if_addr, if_addr);
		}
	}

	/* closing and cleaning everything */
quit:
	if(s_ssdp >= 0) {
		close(s_ssdp);
		s_ssdp = -1;
	}
#ifdef ENABLE_IPV6
	if(s_ssdp6 >= 0) {
		close(s_ssdp6);
		s_ssdp6 = -1;
	}
#endif
	if(s_unix >= 0) {
		close(s_unix);
		s_unix = -1;
		if(unlink(sockpath) < 0)
			syslog(LOG_ERR, "unlink(%s): %m", sockpath);
	}
	if(s_ifacewatch >= 0) {
		close(s_ifacewatch);
		s_ifacewatch = -1;
	}
	if(unlink(pidfilename) < 0)
		syslog(LOG_ERR, "unlink(%s): %m", pidfilename);
	closelog();
	return ret;
}

