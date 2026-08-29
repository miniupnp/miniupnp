/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include "upnphttp.h"
#include "upnputils.h"
#include "miniupnpdtypes.h"

char * os_version = NULL;
int runtime_flags = 0;
time_t startup_time;
struct lan_addr_list lan_addrs;

char *
genRootDesc(int * len, int force_igd1)
{
	static const char desc[] = "rootDesc";
	(void)force_igd1;

	*len = sizeof(desc) - 1;
	return strdup(desc);
}

char *
genWANIPCn(int *, int)
{
	return NULL;
}

char *
genWANCfg(int *, int)
{
	return NULL;
}

char *
genL3F(int *, int)
{
	return NULL;
}

char *
gen6FC(int *, int)
{
	return NULL;
}

#ifdef ENABLE_EVENTS
const char *
upnpevents_addSubscriber(const char *, const char *, int, int)
{
	return NULL;
}

int
upnpevents_removeSubscriber(const char *, int)
{
	return 0;
}

const char *
upnpevents_renewSubscription(const char *, int, int)
{
	return NULL;
}
#endif /* ENABLE_EVENTS */

void
ExecuteSoapAction(struct upnphttp * h, const char * action, int n)
{
	int r;
	printf("action : %.*s\n", n, action);
	r = BuildHeader_upnphttp(h, 200, "OK", n);
	if(r >= 0) {
		memcpy(h->res_buf + h->res_buflen, action, n);
		h->res_buflen += n;
	} else {
		BuildResp2_upnphttp(h, 500, "Internal Server Error", NULL, 0);
	}
	SendRespAndClose_upnphttp(h);
}

int main(int argc, char * * argv)
{
	int i;
	int s;
	unsigned short port = 0;
	struct sockaddr_in listenname;
	fd_set readset;	/* for select() */
	fd_set writeset;
	int max_fd;
	LIST_HEAD(httplisthead, upnphttp) upnphttphead;

	for(i = 1; i < argc; i++) {
		if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			printf("Usage: %s [-p port]\n", argv[0]);
			return 0;
		}
		if(strcmp(argv[i], "-p") == 0 && (i + 1) < argc) {
			port = atoi(argv[++i]);
		} else {
			fprintf(stderr, "unrecognized argument : %s\n", argv[i]);
			return 1;
		}
	}

	LIST_INIT(&upnphttphead);
	openlog("testupnphttp", LOG_CONS|LOG_PERROR, LOG_USER);

	startup_time = time(NULL);
	/* TODO :
	 1 - socket/listen + socket/accept
     2 - appel à upnphttp
     */
	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		syslog(LOG_ERR, "socket(http): %m");
		return 1;
	}
	i = 1;
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0) {
		syslog(LOG_WARNING, "setsockopt(http, SO_REUSEADDR): %m");
	}
	if(!set_non_blocking(s)) {
		syslog(LOG_WARNING, "set_non_blocking(http): %m");
	}
	memset(&listenname, 0, sizeof(struct sockaddr_in));
	listenname.sin_family = AF_INET;
	listenname.sin_port = htons(port);
	listenname.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(s, (struct sockaddr *)&listenname, sizeof(struct sockaddr_in)) < 0) {
		syslog(LOG_ERR, "bind(http): %m");
		close(s);
		return 1;
	}
	if(listen(s, 5) < 0) {
		syslog(LOG_ERR, "listen(http): %m");
		close(s);
		return 1;
	}
	if(port == 0) {
		struct sockaddr_in sockinfo;
		socklen_t len = sizeof(struct sockaddr_in);
		if (getsockname(s, (struct sockaddr *)&sockinfo, &len) < 0) {
			syslog(LOG_ERR, "getsockname(): %m");
		} else {
			port = ntohs(sockinfo.sin_port);
		}
	}
	printf("Listening on port %hu\n", port);
	fflush(stdout);

	for (;;) {
		struct upnphttp * e;

		FD_ZERO(&readset);
		FD_ZERO(&writeset);
		FD_SET(s, &readset);
		max_fd = s;
		for(e = upnphttphead.lh_first; e != NULL; e = e->entries.le_next) {
			if(e->socket >= 0) {
				if(e->state <= EWaitingForHttpContent)
					FD_SET(e->socket, &readset);
				else if(e->state == ESendingAndClosing)
					FD_SET(e->socket, &writeset);
				else
					continue;
				max_fd = MAX(max_fd, e->socket);
			}
		}
		if(select(max_fd+1, &readset, &writeset, 0, NULL) < 0) {
			syslog(LOG_ERR, "select(): %m");
		} else {
			if(FD_ISSET(s, &readset)) {
				struct sockaddr_in clientname;
				socklen_t clientnamelen = sizeof(struct sockaddr_in);
				int shttp = accept(s, (struct sockaddr *)&clientname, &clientnamelen);
				if(shttp < 0) {
					syslog(LOG_ERR, "accept(http): %m");
				} else {
					char addr_str[64];

					sockaddr_to_string((struct sockaddr *)&clientname, addr_str, sizeof(addr_str));
					syslog(LOG_DEBUG, "HTTP connection from %s", addr_str);
					e = New_upnphttp(shttp);
					if(e) {
						e->clientaddr = clientname.sin_addr;
						memcpy(e->clientaddr_str, addr_str, sizeof(e->clientaddr_str));
						LIST_INSERT_HEAD(&upnphttphead, e, entries);
					} else {
						syslog(LOG_ERR, "New_upnphttp() failed");
						close(shttp);
					}
				}
			}
			for(e = upnphttphead.lh_first; e != NULL; e = e->entries.le_next) {
				if(e->socket >= 0 &&
				   (FD_ISSET(e->socket, &readset) || FD_ISSET(e->socket, &writeset))) {
					Process_upnphttp(e);
				}
			}
			/* delete finished HTTP connections */
			for(e = upnphttphead.lh_first; e != NULL; ) {
				struct upnphttp * next = e->entries.le_next;
				if(e->state >= EToDelete) {
					LIST_REMOVE(e, entries);
					Delete_upnphttp(e);
				}
				e = next;
			}
		}
	}

	close(s);

	return 0;
}
