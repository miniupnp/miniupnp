/* $Id: upnpc-libevent.c,v 1.3 2014/11/12 14:10:52 nanard Exp $ */
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "miniupnpc-libevent.h"

static struct event_base *base = NULL;

static void sighandler(int signal)
{
	printf("signal %d\n", signal);
	event_base_loopbreak(base);
}

static void ready(int code, void * data)
{
	upnpc_t * p = (upnpc_t *)data;
	printf("READY ! %d %p\n", code, data);
	/* 1st request */
	upnpc_get_external_ip_address(p);
}

static enum { EGetExtIp = 0, EGetMaxRate, EAddPortMapping, EFinished } state = EGetExtIp;

static void soap(int code, void * data)
{
	upnpc_t * p = (upnpc_t *)data;
	printf("SOAP ! %d\n", code);
	if(code == 200) {
		switch(state) {
		case EGetExtIp:
			printf("ExternalIpAddres=%s\n", GetValueFromNameValueList(&p->soap_response_data, "NewExternalIPAddress"));
			upnpc_get_link_layer_max_rate(p);
			state = EGetMaxRate;
			break;
		case EGetMaxRate:
			printf("DownStream MaxBitRate = %s\t", GetValueFromNameValueList(&p->soap_response_data, "NewLayer1DownstreamMaxBitRate"));
			upnpc_add_port_mapping(p, NULL, 60001, 60002, "192.168.0.42", "TCP", "test port mapping", 0);
			printf("UpStream MaxBitRate = %s\n", GetValueFromNameValueList(&p->soap_response_data, "NewLayer1UpstreamMaxBitRate"));
			state = EAddPortMapping;
			break;
		case EAddPortMapping:
			printf("OK!\n");
		default:
			event_base_loopbreak(base);
		}
	} else {
		printf("SOAP error :\n");
		printf("  faultcode='%s'\n", GetValueFromNameValueList(&p->soap_response_data, "faultcode"));
		printf("  faultstring='%s'\n", GetValueFromNameValueList(&p->soap_response_data, "faultstring"));
		printf("  errorCode=%s\n", GetValueFromNameValueList(&p->soap_response_data, "errorCode"));
		printf("  errorDescription='%s'\n", GetValueFromNameValueList(&p->soap_response_data, "errorDescription"));
		event_base_loopbreak(base);
	}
}

int main(int argc, char * * argv)
{
	struct sigaction sa;
	upnpc_t upnp;
	char * multicast_if = NULL;

	if(argc > 1) {
		multicast_if = argv[1];
	}

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = sighandler;
	if(sigaction(SIGINT, &sa, NULL) < 0) {
		perror("sigaction");
	}
#ifdef DEBUG
	event_enable_debug_mode();
#endif /* DEBUG */
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
	event_enable_debug_logging(EVENT_DBG_ALL);	/* Libevent 2.1.1 */
#endif
	printf("Using libevent %s\n", event_get_version());
	if(LIBEVENT_VERSION_NUMBER != event_get_version_number()) {
		fprintf(stderr, "WARNING build using libevent %s", LIBEVENT_VERSION);
	}

	base = event_base_new();
	if(base == NULL) {
		fprintf(stderr, "event_base_new() failed\n");
		return 1;
	}
#ifdef DEBUG
	printf("Using Libevent with backend method %s.\n",
        event_base_get_method(base));
#endif /* DEBUG */

	if(upnpc_init(&upnp, base, multicast_if, ready, soap, &upnp) != UPNPC_OK) {
		fprintf(stderr, "upnpc_init() failed\n");
		return 1;
	}

	event_base_dispatch(base);	/* TODO : check return value */
	printf("finishing...\n");

	upnpc_finalize(&upnp);
	event_base_free(base);

#if LIBEVENT_VERSION_NUMBER >= 0x02010100
	libevent_global_shutdown();	/* Libevent 2.1.1 */
#endif
	return 0;
}

