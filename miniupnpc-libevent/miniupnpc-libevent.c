/* $Id: miniupnpc-libevent.c,v 1.7 2014/11/12 14:10:52 nanard Exp $ */
/* miniupnpc-libevent
 * Copyright (c) 2008-2014, Thomas BERNARD <miniupnp@free.fr>
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <event2/event.h>
#include <event2/buffer.h>
/*#include <event2/bufferevent.h>*/
#include <event2/http.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#define PRINT_SOCKET_ERROR printf
#define SOCKET_ERROR GetWSALastError()
#define WOULDBLOCK(err) (err == WSAEWOULDBLOCK)
#else
#include <unistd.h>
#include <errno.h>
#define closesocket close
#define PRINT_SOCKET_ERROR perror
#define SOCKET_ERROR errno
#define WOULDBLOCK(err) (err == EAGAIN || err == EWOULDBLOCK)
#endif
#include "miniupnpc-libevent.h"
#include "parsessdpreply.h"
/*#include "upnputils.h"*/
#include "minixml.h"
#include "igd_desc_parse.h"
#include "upnpreplyparse.h"

#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif /* MIN */

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif /* MAXHOSTNAMELEN */

#define SSDP_PORT 1900
#define SSDP_MCAST_ADDR "239.255.255.250"
#define XSTR(s) STR(s)
#define STR(s) #s

#ifdef DEBUG
#define debug_printf(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug_printf(...)
#endif

/* stuctures */

struct upnp_args {
	const char * elt;
	const char * val;
};

/* private functions */

static int upnpc_get_desc(upnpc_t * p, const char * url);
static char * build_url_string(const char * urlbase, const char * root_desc_url, const char * controlurl);

/* data */
static const char * devices_to_search[] = {
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
	"upnp:rootdevice",
	0
};

static void upnpc_conn_close_cb(struct evhttp_connection * conn, void * data)
{
	upnpc_t * p = (upnpc_t *)data;
	debug_printf("upnpc_get_desc_conn_close_cb %p %p\n", conn, p);
}

/* parse_msearch_reply()
 * the last 4 arguments are filled during the parsing :
 *    - location/locationsize : "location:" field of the SSDP reply packet
 *    - st/stsize : "st:" field of the SSDP reply packet.
 * The strings are NOT null terminated */
static void
parse_msearch_reply(const char * reply, int size,
                    const char * * location, int * locationsize,
                    const char * * st, int * stsize)
{
	int a, b, i;
	i = 0;	/* current character index */
	a = i;	/* start of the line */
	b = 0;	/* end of the "header" (position of the colon) */
	while(i<size) {
		switch(reply[i]) {
		case ':':
			if(b==0) {
				b = i; /* end of the "header" */
			}
			break;
		case '\x0a':
		case '\x0d':
			if(b!=0) {
				/* skip the colon and white spaces */
				do { b++; } while(reply[b]==' ' && b<size);
				if(0==strncasecmp(reply+a, "location", 8)) {
					*location = reply+b;
					*locationsize = i-b;
				} else if(0==strncasecmp(reply+a, "st", 2)) {
					*st = reply+b;
					*stsize = i-b;
				}
				b = 0;
			}
			a = i+1;
			break;
		default:
			break;
		}
		i++;
	}
}

static void upnpc_send_ssdp_msearch(evutil_socket_t s, short events, upnpc_t * p)
{
	/* envoyer les packets de M-SEARCH discovery sur le socket ssdp */
	int n;
	char bufr[1024];
	struct sockaddr_in addr;
	unsigned int mx = 2;
	static const char MSearchMsgFmt[] = 
	"M-SEARCH * HTTP/1.1\r\n"
	"HOST: " SSDP_MCAST_ADDR ":" XSTR(SSDP_PORT) "\r\n"
	"ST: %s\r\n"
	"MAN: \"ssdp:discover\"\r\n"
	"MX: %u\r\n"
	"\r\n";
	(void)p;
	(void)events;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
    addr.sin_port = htons(SSDP_PORT);
    addr.sin_addr.s_addr = inet_addr(SSDP_MCAST_ADDR);
	n = snprintf(bufr, sizeof(bufr),
	             MSearchMsgFmt, devices_to_search[0], mx);
	debug_printf("upnpc_send_ssdp_msearch: %s", bufr);
	n = sendto(s, bufr, n, 0,
	           (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (n < 0) {
		PRINT_SOCKET_ERROR("sendto");
	}
}

static int upnpc_set_root_desc_location(upnpc_t * p, const char * location, int locationsize)
{
	char * tmp;
	tmp = realloc(p->root_desc_location, locationsize + 1);
	if(tmp == 0) {
		return -1;
	}
	memcpy(tmp, location, locationsize);
	tmp[locationsize] = '\0';
	p->root_desc_location = tmp;
	return 0;
}

static void upnpc_receive_and_parse_ssdp(evutil_socket_t s, short events, upnpc_t * p)
{
	char bufr[2048];
	ssize_t len;

	if(events == EV_TIMEOUT) {
		/* nothing received ... */
		debug_printf("upnpc_receive_and_parse_ssdp() TIMEOUT\n");
		return;
	}
	len = recv(s, bufr, sizeof(bufr), 0);
	debug_printf("input %d bytes\n", (int)len);
	if(len < 0) {
		PRINT_SOCKET_ERROR("recv");
	} else if(len == 0) {
		debug_printf("SSDP socket closed ?\n");
	} else {
		const char * location = NULL;
		int locationsize;
		const char * st = NULL;
		int stsize;
		debug_printf("%.*s", (int)len, bufr);
		parse_msearch_reply(bufr, len, &location, &locationsize, &st, &stsize);
		debug_printf("location = '%.*s'\n", locationsize, location);
		debug_printf("st = '%.*s'\n", stsize, st);
		if(location != NULL) {
			if(upnpc_set_root_desc_location(p, location, locationsize) < 0) {
				return;
			}
			upnpc_get_desc(p, p->root_desc_location);
		} else {
			/* or do nothing ? */
		}
	}
}

static int
parseURL(const char * url,
         char * hostname, unsigned short * port,
         char * * path, unsigned int * scope_id)
{
	char * p1, *p2, *p3;
	if(!url)
		return 0;
	p1 = strstr(url, "://");
	if(!p1)
		return 0;
	p1 += 3;
	if(  (url[0]!='h') || (url[1]!='t')
	   ||(url[2]!='t') || (url[3]!='p'))
		return 0;
	memset(hostname, 0, MAXHOSTNAMELEN + 1);
	if(*p1 == '[') {
		/* IP v6 : http://[2a00:1450:8002::6a]/path/abc */
		char * scope;
		scope = strchr(p1, '%');
		p2 = strchr(p1, ']');
		if(p2 && scope && scope < p2 && scope_id) {
			/* parse scope */
#ifdef IF_NAMESIZE
			char tmp[IF_NAMESIZE];
			int l;
			scope++;
			/* "%25" is just '%' in URL encoding */
			if(scope[0] == '2' && scope[1] == '5')
				scope += 2;	/* skip "25" */
			l = p2 - scope;
			if(l >= IF_NAMESIZE)
				l = IF_NAMESIZE - 1;
			memcpy(tmp, scope, l);
			tmp[l] = '\0';
			*scope_id = if_nametoindex(tmp);
			if(*scope_id == 0) {
				*scope_id = (unsigned int)strtoul(tmp, NULL, 10);
			}
#else
			/* under windows, scope is numerical */
			char tmp[8];
			int l;
			scope++;
			/* "%25" is just '%' in URL encoding */
			if(scope[0] == '2' && scope[1] == '5')
				scope += 2;	/* skip "25" */
			l = p2 - scope;
			if(l >= (int)sizeof(tmp))
				l = sizeof(tmp) - 1;
			memcpy(tmp, scope, l);
			tmp[l] = '\0';
			*scope_id = (unsigned int)strtoul(tmp, NULL, 10);
#endif
		}
		p3 = strchr(p1, '/');
		if(p2 && p3) {
			p2++;
			strncpy(hostname, p1, MIN(MAXHOSTNAMELEN, (int)(p2-p1)));
			if(*p2 == ':') {
				*port = 0;
				p2++;
				while( (*p2 >= '0') && (*p2 <= '9')) {
					*port *= 10;
					*port += (unsigned short)(*p2 - '0');
					p2++;
				}
			} else {
				*port = 80;
			}
			*path = p3;
			return 1;
		}
	}
	p2 = strchr(p1, ':');
	p3 = strchr(p1, '/');
	if(!p3)
		return 0;
	if(!p2 || (p2>p3)) {
		strncpy(hostname, p1, MIN(MAXHOSTNAMELEN, (int)(p3-p1)));
		*port = 80;
	} else {
		strncpy(hostname, p1, MIN(MAXHOSTNAMELEN, (int)(p2-p1)));
		*port = 0;
		p2++;
		while( (*p2 >= '0') && (*p2 <= '9')) {
			*port *= 10;
			*port += (unsigned short)(*p2 - '0');
			p2++;
		}
	}
	*path = p3;
	return 1;
}

static void upnpc_desc_received(struct evhttp_request * req, void * pvoid)
{
	size_t len;
	unsigned char * data;
	struct evbuffer * input_buffer;
	struct IGDdatas igd;
	struct xmlparser parser;
	upnpc_t * p = (upnpc_t *)pvoid;

	input_buffer = evhttp_request_get_input_buffer(req);
	len = evbuffer_get_length(input_buffer);
	data = evbuffer_pullup(input_buffer, len);
	debug_printf("upnpc_desc_received %d (%d bytes)\n", evhttp_request_get_response_code(req), (int)len);
	debug_printf("%.*s\n", (int)len, (char *)data);
	if(data == NULL)
		return;

	memset(&igd, 0, sizeof(struct IGDdatas));
	memset(&parser, 0, sizeof(struct xmlparser));
	parser.xmlstart = (char *)data;
	parser.xmlsize = len;
	parser.data = &igd;
	parser.starteltfunc = IGDstartelt;
	parser.endeltfunc = IGDendelt;
	parser.datafunc = IGDdata;
	parsexml(&parser);
#ifdef DEBUG
	printIGD(&igd);
#endif /* DEBUG */
	p->control_conn_url = build_url_string(igd.urlbase, p->root_desc_location, igd.first.controlurl);
	p->control_cif_url = build_url_string(igd.urlbase, p->root_desc_location, igd.CIF.controlurl);
	debug_printf("control_conn_url='%s'\n", p->control_conn_url);
	debug_printf("control_cif_url='%s'\n", p->control_cif_url);
	p->ready_cb(evhttp_request_get_response_code(req), p->cb_data);
}

static void upnpc_soap_response(struct evhttp_request * req, void * pvoid)
{
	size_t len;
	unsigned char * data;
	struct evbuffer * input_buffer;
	upnpc_t * p = (upnpc_t *)pvoid;

	input_buffer = evhttp_request_get_input_buffer(req);
	len = evbuffer_get_length(input_buffer);
	data = evbuffer_pullup(input_buffer, len);
	debug_printf("upnpc_soap_response %d (%d bytes)\n", evhttp_request_get_response_code(req), (int)len);
	debug_printf("%.*s\n", (int)len, (char *)data);
	if(data == NULL)
		return;

	ClearNameValueList(&p->soap_response_data);
	ParseNameValue((char *)data, (int)len, 
	               &p->soap_response_data);
	p->soap_cb(evhttp_request_get_response_code(req), p->cb_data);
}

static int upnpc_get_desc(upnpc_t * p, const char * url)
{
	char hostname[MAXHOSTNAMELEN+1];
	unsigned short port;
	char * path;
	unsigned int scope_id;
	struct evhttp_request * req;
	struct evkeyvalq * headers;

	if(p->root_desc_location == 0) {
		return -1;
	}
	if(!parseURL(url/*p->root_desc_location*/, hostname, &port,
	             &path, &scope_id)) {
		return -1;
	}
	if(p->desc_conn == NULL) {
		p->desc_conn = evhttp_connection_base_new(p->base, NULL, hostname, port);
	}
	evhttp_connection_set_closecb(p->desc_conn, upnpc_conn_close_cb, p);
	req = evhttp_request_new(upnpc_desc_received/*callback*/, p);
	headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(headers, "Host", hostname);
	evhttp_add_header(headers, "Connection", "close");
	/*evhttp_connection_set_timeout(req->evcon, 600);*/
	evhttp_make_request(p->desc_conn, req, EVHTTP_REQ_GET, path);
	return 0;
}

#if 0
static int upnpc_complete_connect(upnpc_t * p)
{
	socklen_t len;
	int err;
	len = sizeof(err);
	if(getsockopt(p->http_socket, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		PRINT_SOCKET_ERROR("getsockopt");
		p->state = EError;
		return -1;
	}
	if(err != 0) {
		debug_printf("connect failed %d\n", err);
		p->state = EError;
		return -1;
	}
	if(p->state == EGetDescConnect)
		p->state = EGetDescRequest;
	else
		p->state = ESoapRequest;
	upnpc_send_request(p);
	return 0;
}
#endif

#if 0
static int upnpc_send_request(upnpc_t * p)
{
	ssize_t n;
	static const char reqfmt[] = "GET %s HTTP/1.1\r\n"
		"Host: %s:%hu\r\n"
		"Connection: Close\r\n"
		"User-Agent: MiniUPnPc-async\r\n"
		"\r\n";
	if(p->http_request == NULL) {
		char hostname[MAXHOSTNAMELEN+1];
		unsigned short port;
		char * path;
		unsigned int scope_id;
		int len;
		if(!parseURL(p->root_desc_location, hostname, &port,
	    	         &path, &scope_id)) {
			p->state = EError;
			return -1;
		}
		len = snprintf(NULL, 0, reqfmt, path, hostname, port);
		p->http_request = malloc(len + 1);
		if(p->http_request == NULL) {
			p->state = EError;
			return -1;
		}
		p->http_request_len = snprintf(p->http_request, len + 1,
		                               reqfmt, path, hostname, port);
		p->http_request_sent = 0;
	}
	n = send(p->http_socket, p->http_request + p->http_request_sent,
	         p->http_request_len - p->http_request_sent, 0/* flags */);
	if(n < 0) {
		PRINT_SOCKET_ERROR("send");
		p->state = EError;
		return -1;
	} else {
		debug_printf("sent %d bytes\n", (int)n);
		/*if(n == 0) {
			p->state = EError;
			return -1;
		}*/
		p->http_request_sent += n;
		if(p->http_request_sent >= p->http_request_len) {
			/* all bytes sent */
#if 0
			shutdown(p->http_socket, SHUT_WR);	/* some routers don't like that */
#endif
			free(p->http_request);
			p->http_request = NULL;
			p->http_request_len = 0;
			if(p->state == EGetDescRequest)
				p->state = EGetDescResponse;
			else
				p->state = ESoapResponse;
			free(p->http_response);
			p->http_response = NULL;
			p->http_response_received = 0;
			p->http_response_end_of_headers = 0;
			/* get response */
		}
	}
	return 0;
}

static int upnpc_parse_headers(upnpc_t * p)
{
	/* search for CR LF CR LF (end of headers)
	 * recognize also LF LF */
	int i = 0;
	while(i < (p->http_response_received-1) &&
	      p->http_response_end_of_headers == 0) {
		if(p->http_response[i] == '\r') {
			i++;
			if(p->http_response[i] == '\n') {
				i++;
				if(i < p->http_response_received && p->http_response[i] == '\r') {
					i++;
					if(i < p->http_response_received && p->http_response[i] == '\n') {
						p->http_response_end_of_headers = i + 1;
					}
				}
			}
		} else if(p->http_response[i] == '\n') {
			i++;
			if(p->http_response[i] == '\n') {
				p->http_response_end_of_headers = i + 1;
			}
		}
		i++;
	}
	if(p->http_response_end_of_headers != 0) {
		int colon = 0;
		int linestart = 0;
		int valuestart = 0;
		p->http_response_code = -1;
		for(i = 0; i < p->http_response_end_of_headers - 1; i++) {
			if(linestart == 0) {
				/* reading HTTP response code on the 1st line */
				if(p->http_response[i] == ' ' && p->http_response_code < 0)
					p->http_response_code = 0;
				else if(p->http_response[i] >= '0' && p->http_response[i] <= '9') {
					p->http_response_code = p->http_response_code * 10 + (p->http_response[i] - '0');
				} else if(p->http_response[i] == ' ')
					linestart = 1;
			}
			if(colon <= linestart && p->http_response[i] == ':') {
				colon = i;
				while(i < p->http_response_end_of_headers - 1 &&
				      (p->http_response[i+1] == ' ' || p->http_response[i+1] == '\t'))
					i++;
				valuestart = i + 1;
			} else if(p->http_response[i + 1] == '\r' ||
			          p->http_response[i + 1] == '\n') {
				if(colon > linestart && valuestart > colon) {
					debug_printf("header='%.*s', value='%.*s'\n",
					       colon-linestart, p->http_response+linestart,
					       i+1-valuestart, p->http_response+valuestart);
					if(0==strncasecmp(p->http_response+linestart, "content-length", colon-linestart)) {
						p->http_response_content_length = atoi(p->http_response + valuestart);
						debug_printf("Content-Length: %d\n", p->http_response_content_length);
						if(p->http_response_content_length < 0) {
							debug_printf("Content-Length overflow ? setting to 0\n");
							p->http_response_content_length = 0;
						}
					} else if(0==strncasecmp(p->http_response+linestart, "transfer-encoding", colon-linestart)
						   && 0==strncasecmp(p->http_response+valuestart, "chunked", 7)) {
						debug_printf("Chunked transfer-encoding !\n");
						p->http_response_chunked = 1;
					}
				}
				/* find next line */
				while((i < p->http_response_received) &&
				      (p->http_response[i]=='\r' || p->http_response[i] == '\n'))
					i++;
				linestart = i;
				colon = linestart;
				valuestart = 0;
			}
		}
	}
	return 0;
}
#endif

static char * build_url_string(const char * urlbase, const char * root_desc_url, const char * controlurl)
{
	int l, n;
	char * s;
	const char * base;
	char * p;
	/* if controlurl is an absolute url, return it */
	if(0 == memcmp("http://", controlurl, 7))
		return strdup(controlurl);
	base = (urlbase[0] == '\0') ? root_desc_url : urlbase;
	n = strlen(base);
	if(n > 7) {
		p = strchr(base + 7, '/');
		if(p)
			n = p - base;
	}
	l = n + strlen(controlurl) + 1;
	if(controlurl[0] != '/')
		l++;
	s = malloc(l);
	if(s == NULL) return NULL;
	memcpy(s, base, n);
	if(controlurl[0] != '/')
		s[n++] = '/';
	memcpy(s + n, controlurl, l - n);
	return s;
}

#if 0
static int upnpc_get_response(upnpc_t * p)
{
	ssize_t n;
	ssize_t count;
	char buffer[2048];
	if(p->http_response_content_length > 0) {
		count = p->http_response_content_length
		      + p->http_response_end_of_headers
		      - p->http_response_received;
		if(count > (ssize_t)sizeof(buffer)) count = sizeof(buffer);
	} else {
		count = sizeof(buffer);
	}
	debug_printf("recv(..., %d)\n", (int)count);
	n = recv(p->http_socket, buffer, count, 0/* flags */);
	if(n < 0) {
		if(errno == EINTR || WOULDBLOCK(errno))
			return 0;	/* try again later */
		PRINT_SOCKET_ERROR("read");
		p->state = EError;
		return -1;
	} else if(n == 0) {
		/* receiving finished */
		debug_printf("%.*s\n", p->http_response_received, p->http_response);
		close(p->http_socket);
		p->http_socket = -1;
		/* parse */
		if(p->http_response_end_of_headers == 0) {
			upnpc_parse_headers(p);
		}
		/* TODO : decode chunked transfer-encoding */
		/* parse xml */
		if(p->state == EGetDescResponse) {
			struct IGDdatas igd;
			struct xmlparser parser;
			memset(&igd, 0, sizeof(struct IGDdatas));
			memset(&parser, 0, sizeof(struct xmlparser));
			parser.xmlstart = p->http_response + p->http_response_end_of_headers;
			parser.xmlsize = p->http_response_received - p->http_response_end_of_headers;
			parser.data = &igd;
			parser.starteltfunc = IGDstartelt;
			parser.endeltfunc = IGDendelt;
			parser.datafunc = IGDdata;
			parsexml(&parser);
#ifdef DEBUG
			printIGD(&igd);
#endif /* DEBUG */
			p->control_conn_url = build_url_string(igd.urlbase, p->root_desc_location, igd.first.controlurl);
			p->control_cif_url = build_url_string(igd.urlbase, p->root_desc_location, igd.CIF.controlurl);
			debug_printf("control_conn_url='%s'\n", p->control_conn_url);
			debug_printf("control_cif_url='%s'\n", p->control_cif_url);
		} else {
			ClearNameValueList(&p->soap_response_data);
			ParseNameValue(p->http_response + p->http_response_end_of_headers,
			               p->http_response_received - p->http_response_end_of_headers,
			               &p->soap_response_data);
		}
		free(p->http_response);
		p->http_response = NULL;
		p->http_response_received = 0;
		p->http_response_end_of_headers = 0;
		p->state = EReady;
	} else {
		/* receiving in progress */
		debug_printf("received %d bytes:\n%.*s\n", (int)n, (int)n, buffer);
		if(p->http_response == NULL) {
			p->http_response = malloc(n);
			if(p->http_response == NULL) {
				debug_printf("failed to malloc %d bytes\n", (int)n);
				p->state = EError;
				return -1;
			}
			p->http_response_received = n;
			memcpy(p->http_response, buffer, n);
		} else {
			char * tmp = realloc(p->http_response, p->http_response_received + n);
			if(tmp == NULL) {
				debug_printf("failed to realloc %d bytes\n", (int)(p->http_response_received + n));
				p->state = EError;
				return -1;
			}
			p->http_response = tmp;
			memcpy(p->http_response + p->http_response_received, buffer, n);
			p->http_response_received += n;
		}
		if(p->http_response_end_of_headers == 0) {
			upnpc_parse_headers(p);
		}
	}
	return 0;
}
#endif

#define SOAPPREFIX "s"
#define SERVICEPREFIX "u"
#define SERVICEPREFIX2 'u'

static int upnpc_send_soap_request(upnpc_t * p, const char * url,
                                   const char * service,
                                   const char * method,
                                   const struct upnp_args * args, int arg_count)
{
	char action[128];
	char * body;
	const char fmt_soap[] = 
		"<?xml version=\"1.0\"?>\r\n"
		"<" SOAPPREFIX ":Envelope "
		"xmlns:" SOAPPREFIX "=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		SOAPPREFIX ":encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<" SOAPPREFIX ":Body>"
		"<" SERVICEPREFIX ":%s xmlns:" SERVICEPREFIX "=\"%s\">"
		"%s"
		"</" SERVICEPREFIX ":%s>"
		"</" SOAPPREFIX ":Body></" SOAPPREFIX ":Envelope>"
		"\r\n";
	int body_len;
#if 0
	const char fmt_http[] =
		"POST %s HTTP/1.1\r\n"
		"Host: %s%s\r\n"
		"User-Agent: MiniUPnPc-async\r\n"
		"Content-Length: %d\r\n"
		"Content-Type: text/xml\r\n"
		"SOAPAction: \"%s#%s\"\r\n"
		"Connection: Close\r\n"
		"Cache-Control: no-cache\r\n"	/* ??? */
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s";
#endif
	char hostname[MAXHOSTNAMELEN+1];
	unsigned short port;
	char * path;
	unsigned int scope_id;
	char portstr[8];
	char * args_xml = NULL;
	struct evhttp_request * req;
	struct evkeyvalq * headers;
	struct evbuffer * buffer;

	if(arg_count > 0) {
		int i;
		size_t l, n;
		for(i = 0, l = 0; i < arg_count; i++) {
			/* <ELT>VAL</ELT> */
			l += strlen(args[i].elt) * 2 + strlen(args[i].val) + 5;
		}
		args_xml = malloc(++l);
		if(args_xml == NULL) {
			return -1;
		}
		for(i = 0, n = 0; i < arg_count && n < l; i++) {
			/* <ELT>VAL</ELT> */
			n += snprintf(args_xml + n, l - n, "<%s>%s</%s>",
			              args[i].elt, args[i].val, args[i].elt);
		}
	}

	body_len = snprintf(NULL, 0, fmt_soap, method, service, args_xml?args_xml:"", method);
	body = malloc(body_len + 1);
	if(body == NULL) {
		return -1;
	}
	if(snprintf(body, body_len + 1, fmt_soap, method, service, args_xml?args_xml:"", method) != body_len) {
		debug_printf("snprintf() returned strange value...\n");
	}
	free(args_xml);
	args_xml = NULL;
	if(!parseURL(url, hostname, &port, &path, &scope_id)) {
		return -1;
	}
	if(port != 80)
		snprintf(portstr, sizeof(portstr), ":%hu", port);
	else
		portstr[0] = '\0';
	snprintf(action, sizeof(action), "%s#%s", service, method);
	if(p->soap_conn == NULL) {
		p->soap_conn = evhttp_connection_base_new(p->base, NULL, hostname, port);
	}
	req = evhttp_request_new(upnpc_soap_response, p);
	headers = evhttp_request_get_output_headers(req);
	buffer = evhttp_request_get_output_buffer(req);
	evhttp_add_header(headers, "Host", hostname);
	evhttp_add_header(headers, "SOAPAction", action);
	evhttp_add_header(headers, "Content-Type", "text/xml");
	evbuffer_add(buffer, body, body_len);
	evhttp_make_request(p->soap_conn, req, EVHTTP_REQ_POST, path);
	free(body);
	return 0;
}

/* public functions */
int upnpc_init(upnpc_t * p, struct event_base * base, const char * multicastif,
               upnpc_callback_fn ready_cb, upnpc_callback_fn soap_cb, void * cb_data)
{
	int opt = 1;
	struct sockaddr_in addr;
	struct timeval timeout;

	if(p == NULL || base == NULL)
		return UPNPC_ERR_INVALID_ARGS;
	memset(p, 0, sizeof(upnpc_t)); /* clean everything */
	p->base = base;
	p->ready_cb = ready_cb;
	p->soap_cb = soap_cb;
	p->cb_data = cb_data;
	/* open the socket for SSDP */
	p->ssdp_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(p->ssdp_socket < 0) {
		return UPNPC_ERR_SOCKET_FAILED;
	}
	/* set REUSEADDR */
#ifdef WIN32
	if(setsockopt(p->ssdp_socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0) {
#else
	if(setsockopt(p->ssdp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
		/* non fatal error ! */
	}
	if(evutil_make_socket_nonblocking(p->ssdp_socket) < 0) {
		debug_printf("evutil_make_socket_nonblocking FAILED\n");
	}

	/* receive address */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	/*addr.sin_port = htons(SSDP_PORT);*/

	if(multicastif) {
		struct in_addr mc_if;
		mc_if.s_addr = inet_addr(multicastif);
    	addr.sin_addr.s_addr = mc_if.s_addr;
		if(setsockopt(p->ssdp_socket, IPPROTO_IP, IP_MULTICAST_IF, (const char *)&mc_if, sizeof(mc_if)) < 0) {
			PRINT_SOCKET_ERROR("setsockopt");
			/* non fatal error ! */
		}
	}

	/* bind the socket to the ssdp address in order to receive responses */
	if(bind(p->ssdp_socket, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0) {
		close(p->ssdp_socket);
		return UPNPC_ERR_BIND_FAILED;
	}
	/* event on SSDP */
	p->ev_ssdp_recv = event_new(p->base, p->ssdp_socket,
	                         EV_READ|EV_PERSIST,
	                         (event_callback_fn)upnpc_receive_and_parse_ssdp, p);
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if(event_add(p->ev_ssdp_recv, &timeout)) {
		debug_printf("event_add FAILED\n");
	}
	p->ev_ssdp_writable = event_new(p->base, p->ssdp_socket,
	                             EV_WRITE,
	                             (event_callback_fn)upnpc_send_ssdp_msearch, p);
	if(event_add(p->ev_ssdp_writable, NULL)) {
		debug_printf("event_add FAILED\n");
	}
	return UPNPC_OK;
}

int upnpc_finalize(upnpc_t * p)
{
	if(!p) return UPNPC_ERR_INVALID_ARGS;
	free(p->root_desc_location);
	p->root_desc_location = NULL;
	free(p->control_cif_url);
	p->control_cif_url = NULL;
	free(p->control_conn_url);
	p->control_conn_url = NULL;
	if(p->ssdp_socket >= 0) {
		close(p->ssdp_socket);
		p->ssdp_socket = -1;
	}
	if(p->ev_ssdp_recv) {
		event_free(p->ev_ssdp_recv);
		p->ev_ssdp_recv = NULL;
	}
	if(p->ev_ssdp_writable) {
		event_free(p->ev_ssdp_writable);
		p->ev_ssdp_writable = NULL;
	}
	if(p->desc_conn) {
		evhttp_connection_free(p->desc_conn);
		p->desc_conn = NULL;
	}
	if(p->soap_conn) {
		evhttp_connection_free(p->soap_conn);
		p->soap_conn = NULL;
	}
#if 0
	if(p->http_socket >= 0) {
		close(p->http_socket);
		p->http_socket = -1;
	}
#endif
	ClearNameValueList(&p->soap_response_data);
	return UPNPC_OK;
}

int upnpc_get_external_ip_address(upnpc_t * p)
{
	return upnpc_send_soap_request(p, p->control_conn_url,
	                         "urn:schemas-upnp-org:service:WANIPConnection:1",
	                         "GetExternalIPAddress", NULL, 0);
}

int upnpc_get_link_layer_max_rate(upnpc_t * p)
{
	return upnpc_send_soap_request(p, p->control_cif_url,
	                         "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
	                         "GetCommonLinkProperties", NULL, 0);
}

int upnpc_add_port_mapping(upnpc_t * p,
                           const char * remote_host, unsigned short ext_port,
                           unsigned short int_port, const char * int_client,
                           const char * proto, const char * description,
                           unsigned int lease_duration)
{
	struct upnp_args args[8];
	char lease_duration_str[16];
	char int_port_str[8];
	char ext_port_str[8];

	if(int_client == NULL || int_port == 0 || ext_port == 0 || proto == NULL)
		return UPNPC_ERR_INVALID_ARGS;
	snprintf(lease_duration_str, sizeof(lease_duration_str), "%u", lease_duration);
	snprintf(int_port_str, sizeof(int_port_str), "%hu", int_port);
	snprintf(ext_port_str, sizeof(ext_port_str), "%hu", ext_port);
	args[0].elt = "NewRemoteHost";
	args[0].val = remote_host?remote_host:"";
	args[1].elt = "NewExternalPort";
	args[1].val = ext_port_str;
	args[2].elt = "NewProtocol";
	args[2].val = proto;
	args[3].elt = "NewInternalPort";
	args[3].val = int_port_str;
	args[4].elt = "NewInternalClient";
	args[4].val = int_client;
	args[5].elt = "NewEnabled";
	args[5].val = "1";
	args[6].elt = "NewPortMappingDescription";
	args[6].val = description?description:"miniupnpc-async";
	args[7].elt = "NewLeaseDuration";
	args[7].val = lease_duration_str;
	return upnpc_send_soap_request(p, p->control_conn_url,
	                         "urn:schemas-upnp-org:service:WANIPConnection:1",
	                         "AddPortMapping",
	                         args, 8);
}

