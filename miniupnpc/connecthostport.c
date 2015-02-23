/* $Id: connecthostport.c,v 1.13 2014/03/31 12:36:36 nanard Exp $ */
/* Project : miniupnp
 * Author : Thomas Bernard
 * Copyright (c) 2010-2014 Thomas Bernard
 * This software is subject to the conditions detailed in the
 * LICENCE file provided in this distribution. */

/* use getaddrinfo() or gethostbyname()
 * uncomment the following line in order to use gethostbyname() */
#ifdef NO_GETADDRINFO
#define USE_GETHOSTBYNAME
#endif

#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#define MAXHOSTNAMELEN 64
#define snprintf _snprintf
#define herror
#define socklen_t int
#else /* #ifdef _WIN32 */
#include <unistd.h>
#include <sys/param.h>
#include <sys/select.h>
#include <errno.h>
#define closesocket close
#include <netdb.h>
#include <netinet/in.h>
/* defining MINIUPNPC_IGNORE_EINTR enable the ignore of interruptions
 * during the connect() call */
#define MINIUPNPC_IGNORE_EINTR
#ifndef USE_GETHOSTBYNAME
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#endif /* #ifndef USE_GETHOSTBYNAME */
#include <fcntl.h>
#endif /* #else _WIN32 */

/* definition of PRINT_SOCKET_ERROR */
#ifdef _WIN32
#define PRINT_SOCKET_ERROR(x)    printf("Socket error: %s, %d\n", x, WSAGetLastError());
#else
#define PRINT_SOCKET_ERROR(x) perror(x)
#endif

#if defined(__amigaos__) || defined(__amigaos4__)
#define herror(A) printf("%s\n", A)
#endif

#include "connecthostport.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef SOCKET_TIMEOUT
#define SOCKET_TIMEOUT 3000
#endif

/* connectAsync()
 * connect the specified socket asynchronously.
 * returns 0 in case of success or -1 in case of error */
static int connectAsync(int s, struct addrinfo *p)
{
	int n;
	/* Set the socket to non-blocking mode */
#ifdef _WIN32
	u_long mode = 1;
	ioctlsocket(s, FIONBIO, &mode);
#else /* #ifdef _WIN32 */
	int flags = fcntl(s, F_GETFL);
	fcntl(s, F_SETFL, flags & ~O_NONBLOCK);
#endif /* #else _WIN32 */
	
	n = connect(s, p->ai_addr, p->ai_addrlen);
#ifdef _WIN32
	if ((n < 0) && (WSAGetLastError() != WSAEWOULDBLOCK))
	{
		return n;
	}
#else /* #ifdef _WIN32 */
	if ((n < 0) && (errno != EINPROGRESS))
	{
		return n;
	}
#endif /* #else _WIN32 */

	if (n == 0)
	{
		/* connection attempt has succeeded immediately */
		return n;
	}
	else
	{
		/* connection attempt is still in progress */
 		fd_set wset;
		struct timeval timeout;
		timeout.tv_sec = SOCKET_TIMEOUT / 1000;
 		timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
 
 		/* Wait for the socket to become writable */
#ifdef MINIUPNPC_IGNORE_EINTR
 		do
		{
#endif
			FD_ZERO(&wset);
			FD_SET(s, &wset);
			n = select(s + 1, NULL, &wset, NULL, &timeout);
#ifdef MINIUPNPC_IGNORE_EINTR
		} while(n < 0 && errno == EINTR);
#endif

		if (n < 0)
		{
			/* There was a socket error */
			PRINT_SOCKET_ERROR("select");
			return n;
		}
		else if (n == 0)
		{
			/* Timeout exceeded */
			return -1;
		}

		if (FD_ISSET(s, &wset))
		{
			return 0;
		}
		return -1;
	}
}
 
/* connecthostport()
 * return a socket connected (TCP) to the host and port
 * or -1 in case of error */
int connecthostport(const char * host, unsigned short port,
                    unsigned int scope_id)
{
	int s, n;
#ifdef USE_GETHOSTBYNAME
	struct sockaddr_in dest;
	struct hostent *hp;
#else /* #ifdef USE_GETHOSTBYNAME */
	char tmp_host[MAXHOSTNAMELEN+1];
	char port_str[8];
	struct addrinfo *ai, *p;
	struct addrinfo hints;
#endif /* #ifdef USE_GETHOSTBYNAME */
#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT
	struct timeval timeout;
#endif /* #ifdef MINIUPNPC_SET_SOCKET_TIMEOUT */

#ifdef USE_GETHOSTBYNAME
	hp = gethostbyname(host);
	if(hp == NULL)
	{
		herror(host);
		return -1;
	}
	memcpy(&dest.sin_addr, hp->h_addr, sizeof(dest.sin_addr));
	memset(dest.sin_zero, 0, sizeof(dest.sin_zero));
	s = socket(PF_INET, SOCK_STREAM, 0);
	if(s < 0)
	{
		PRINT_SOCKET_ERROR("socket");
		return -1;
	}
#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT
	/* setting a timeout for the connect() call */
	/* TODO setting a timeout on the socket doesn't work for the connect() call. Now the client
	   is made to work asynchronously this code can probably be removed.*/
	timeout.tv_sec = SOCKET_TIMEOUT / 1000;
	timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(struct timeval)) < 0)
	{
		PRINT_SOCKET_ERROR("setsockopt");
	}
	timeout.tv_sec = SOCKET_TIMEOUT / 1000;
	timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
	if(setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(struct timeval)) < 0)
	{
		PRINT_SOCKET_ERROR("setsockopt");
	}
#endif /* #ifdef MINIUPNPC_SET_SOCKET_TIMEOUT */
	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	n = connectAsync(s, &dest);
	if(n<0)
	{
		PRINT_SOCKET_ERROR("connect");
		closesocket(s);
		return -1;
	}
#else /* #ifdef USE_GETHOSTBYNAME */
	/* use getaddrinfo() instead of gethostbyname() */
	memset(&hints, 0, sizeof(hints));
	/* hints.ai_flags = AI_ADDRCONFIG; */
#ifdef AI_NUMERICSERV
	hints.ai_flags = AI_NUMERICSERV;
#endif
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC; /* AF_INET, AF_INET6 or AF_UNSPEC */
	/* hints.ai_protocol = IPPROTO_TCP; */
	snprintf(port_str, sizeof(port_str), "%hu", port);
	if(host[0] == '[')
	{
		/* literal ip v6 address */
		int i, j;
		for(i = 0, j = 1; host[j] && (host[j] != ']') && i < MAXHOSTNAMELEN; i++, j++)
		{
			tmp_host[i] = host[j];
			if(0 == memcmp(host+j, "%25", 3))	/* %25 is just url encoding for '%' */
				j+=2;							/* skip "25" */
		}
		tmp_host[i] = '\0';
	}
	else
	{
		strncpy(tmp_host, host, MAXHOSTNAMELEN);
	}
	tmp_host[MAXHOSTNAMELEN] = '\0';
	n = getaddrinfo(tmp_host, port_str, &hints, &ai);
	if(n != 0)
	{
#ifdef _WIN32
		fprintf(stderr, "getaddrinfo() error : %d\n", n);
#else
		fprintf(stderr, "getaddrinfo() error : %s\n", gai_strerror(n));
#endif
		return -1;
	}
	s = -1;
	for(p = ai; p; p = p->ai_next)
	{
		s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if(s < 0)
			continue;
		if(p->ai_addr->sa_family == AF_INET6 && scope_id > 0) {
			struct sockaddr_in6 * addr6 = (struct sockaddr_in6 *)p->ai_addr;
			addr6->sin6_scope_id = scope_id;
		}
#ifdef MINIUPNPC_SET_SOCKET_TIMEOUT
		/* setting a timeout for the connect() call */
		/* TODO setting a timeout on the socket doesn't work for the connect() call. Now the client
	       is made to work asynchronously this code can probably be removed.*/
		timeout.tv_sec = SOCKET_TIMEOUT / 1000;
		timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
		if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(struct timeval)) < 0)
		{
			PRINT_SOCKET_ERROR("setsockopt");
		}
		timeout.tv_sec = SOCKET_TIMEOUT / 1000;
		timeout.tv_usec = (SOCKET_TIMEOUT % 1000) * 1000;
		if(setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout, sizeof(struct timeval)) < 0)
		{
			PRINT_SOCKET_ERROR("setsockopt");
		}
#endif /* #ifdef MINIUPNPC_SET_SOCKET_TIMEOUT */
		n = connectAsync(s, p);
		if(n < 0)
		{
			closesocket(s);
			continue;
		}
		else
		{
			break;
		}
	}
	freeaddrinfo(ai);
	if(s < 0)
	{
		PRINT_SOCKET_ERROR("socket");
		return -1;
	}
	if(n < 0)
	{
		PRINT_SOCKET_ERROR("connect");
		return -1;
	}
#endif /* #ifdef USE_GETHOSTBYNAME */
	return s;
}

