/* $Id: minissdpc.c,v 1.15 2012/01/21 13:30:31 nanard Exp $ */
/* Project : miniupnp
 * Web : http://miniupnp.free.fr/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2015 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */
/*#include <syslog.h>*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__amigaos__) || defined(__amigaos4__)
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <winsock.h>
#include <stdint.h>
#endif
#if defined(__amigaos__) || defined(__amigaos4__)
#include <sys/socket.h>
#endif
#if defined(__amigaos__)
#define uint16_t unsigned short
#endif
/* Hack */
#define UNIX_PATH_LEN   108
struct sockaddr_un {
  uint16_t sun_family;
  char     sun_path[UNIX_PATH_LEN];
};
#else
#include <sys/socket.h>
#include <sys/un.h>
#endif

#include "minissdpc.h"
#include "miniupnpc.h"

#include "codelength.h"

struct UPNPDev *
getDevicesFromMiniSSDPD(const char * devtype, const char * socketpath, int * error)
{
	struct UPNPDev * devlist;
	int s;
	int res;

	s = connectToMiniSSDPD(socketpath);
	if (s < 0) {
		if (error)
			*error = s;
		return NULL;
	}
	res = requestDevicesFromMiniSSDPD(s, devtype);
	if (res < 0) {
		if (error)
			*error = res;
		return NULL;
	}
	devlist = receiveDevicesFromMiniSSDPD(s, error);
	disconnectFromMiniSSDPD(s);
	return devlist;
}

/* macros used to read from unix socket */
#define READ_BYTE_BUFFER(c) \
	if(bufferindex >= n) { \
		n = read(s, buffer, sizeof(buffer)); \
		if(n<=0) break; \
		bufferindex = 0; \
	} \
	c = buffer[bufferindex++];

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif /* MIN */

#define READ_COPY_BUFFER(dst, len) \
	for(l = len, p = (unsigned char *)dst; l > 0; ) { \
		unsigned int lcopy; \
		if(bufferindex >= n) { \
			n = read(s, buffer, sizeof(buffer)); \
			if(n<=0) break; \
			bufferindex = 0; \
		} \
		lcopy = MIN(l, (n - bufferindex)); \
		memcpy(p, buffer + bufferindex, lcopy); \
		l -= lcopy; \
		p += lcopy; \
		bufferindex += lcopy; \
	}

#define READ_DISCARD_BUFFER(len) \
	for(l = len; l > 0; ) { \
		unsigned int lcopy; \
		if(bufferindex >= n) { \
			n = read(s, buffer, sizeof(buffer)); \
			if(n<=0) break; \
			bufferindex = 0; \
		} \
		lcopy = MIN(l, (n - bufferindex)); \
		l -= lcopy; \
		bufferindex += lcopy; \
	}

int
connectToMiniSSDPD(const char * socketpath)
{
	int s;
	struct sockaddr_un addr;
#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT
	struct timeval timeout;
#endif /* #ifdef MINIUPNPC_SET_SOCKET_TIMEOUT */

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s < 0)
	{
		/*syslog(LOG_ERR, "socket(unix): %m");*/
		perror("socket(unix)");
		return MINISSDPC_SOCKET_ERROR;
	}
#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT
	/* setting a 3 seconds timeout */
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		perror("setsockopt");
	}
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval)) < 0)
	{
		perror("setsockopt");
	}
#endif /* #ifdef MINIUPNPC_SET_SOCKET_TIMEOUT */
	if(!socketpath)
		socketpath = "/var/run/minissdpd.sock";
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socketpath, sizeof(addr.sun_path));
	/* TODO : check if we need to handle the EINTR */
	if(connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0)
	{
		/*syslog(LOG_WARNING, "connect(\"%s\"): %m", socketpath);*/
		return MINISSDPC_SOCKET_ERROR;
	}
	return s;
}

int
disconnectFromMiniSSDPD(int s)
{
	if (close(s) < 0)
		return MINISSDPC_SOCKET_ERROR;
	return MINISSDPC_SUCCESS;
}

int
requestDevicesFromMiniSSDPD(int s, const char * devtype)
{
	unsigned char buffer[256];
	unsigned char * p;
	unsigned int stsize, l;

	stsize = strlen(devtype);
	if(stsize == 8 && 0 == memcmp(devtype, "ssdp:all", 8))
	{
		buffer[0] = 3;	/* request type 3 : everything */
	}
	else
	{
		buffer[0] = 1; /* request type 1 : request devices/services by type */
	}
	p = buffer + 1;
	l = stsize;	CODELENGTH(l, p);
	if(p + stsize > buffer + sizeof(buffer))
	{
		/* devtype is too long ! */
#ifdef DEBUG
		fprintf(stderr, "devtype is too long ! stsize=%u sizeof(buffer)=%u\n",
		        stsize, (unsigned)sizeof(buffer));
#endif /* DEBUG */
		return MINISSDPC_INVALID_INPUT;
	}
	memcpy(p, devtype, stsize);
	p += stsize;
	if(write(s, buffer, p - buffer) < 0)
	{
		/*syslog(LOG_ERR, "write(): %m");*/
		perror("minissdpc.c: write()");
		return MINISSDPC_SOCKET_ERROR;
	}
	return MINISSDPC_SUCCESS;
}

struct UPNPDev *
receiveDevicesFromMiniSSDPD(int s, int * error)
{
	struct UPNPDev * tmp;
	struct UPNPDev * devlist = NULL;
	unsigned char buffer[256];
	ssize_t n;
	unsigned char * p;
	unsigned char * url;
	unsigned char * st;
	unsigned int bufferindex;
	unsigned int i, ndev;
	unsigned int urlsize, stsize, usnsize, l;

	n = read(s, buffer, sizeof(buffer));
	if(n<=0)
	{
		perror("minissdpc.c: read()");
		if (error)
			*error = MINISSDPC_SOCKET_ERROR;
		return NULL;
	}
	ndev = buffer[0];
	bufferindex = 1;
	for(i = 0; i < ndev; i++)
	{
		DECODELENGTH_READ(urlsize, READ_BYTE_BUFFER);
		if(n<=0) {
			break;
		}
#ifdef DEBUG
		printf("  urlsize=%u", urlsize);
#endif /* DEBUG */
		url = malloc(urlsize);
		if(url == NULL) {
			break;
		}
		READ_COPY_BUFFER(url, urlsize);
		if(n<=0) {
			free(url);
			break;
		}
		DECODELENGTH_READ(stsize, READ_BYTE_BUFFER);
		if(n<=0) {
			free(url);
			break;
		}
#ifdef DEBUG
		printf("   stsize=%u", stsize);
#endif /* DEBUG */
		st = malloc(stsize);
		if (st == NULL) {
			free(url);
			break;
		}
		READ_COPY_BUFFER(st, stsize);
		if(n<=0) {
			free(url);
			free(st);
			break;
		}
		DECODELENGTH_READ(usnsize, READ_BYTE_BUFFER);
		if(n<=0) {
			free(url);
			free(st);
			break;
		}
#ifdef DEBUG
		printf("   usnsize=%u\n", usnsize);
#endif /* DEBUG */
		tmp = (struct UPNPDev *)malloc(sizeof(struct UPNPDev)+urlsize+stsize+usnsize);
		if(tmp == NULL) {
			free(url);
			free(st);
			break;
		}
		tmp->pNext = devlist;
		tmp->descURL = tmp->buffer;
		tmp->st = tmp->buffer + 1 + urlsize;
		memcpy(tmp->buffer, url, urlsize);
		tmp->buffer[urlsize] = '\0';
		memcpy(tmp->st, st, stsize);
		tmp->buffer[urlsize+1+stsize] = '\0';
		free(url);
		free(st);
		url = NULL;
		st = NULL;
		tmp->usn = tmp->buffer + 1 + urlsize + 1 + stsize;
		READ_COPY_BUFFER(tmp->usn, usnsize);
		if(n<=0) {
			free(tmp);
			break;
		}
		tmp->buffer[urlsize+1+stsize+1+usnsize] = '\0';
		tmp->scope_id = 0;	/* default value. scope_id is not available with MiniSSDPd */
		devlist = tmp;
	}
	if (error)
		*error = MINISSDPC_SUCCESS;
	return devlist;
}

