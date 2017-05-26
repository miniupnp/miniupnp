/* $Id: testasync.c,v 1.14 2014/11/07 12:07:38 nanard Exp $ */
/* miniupnpc-async
 * Copyright (c) 2008-2017, Thomas BERNARD <miniupnp@free.fr>
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
#include <sys/select.h>
/* for getnameinfo() : */
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
/* compile with -DUPNPC_USE_SELECT to enable upnpc_select_fds() function */
#include "miniupnpc-async.h"
#include "upnpreplyparse.h"

enum methods {
	EGetExternalIP,
	EGetRates,
	EAddPortMapping,
	ENothing
};

int main(int argc, char * * argv)
{
	char ip_address[64];
	int r, n;
	upnpc_t upnp;
	const char * multicastif = NULL;
	enum methods next_method_to_call = EGetExternalIP;
	enum methods last_method = ENothing;
	if(argc>1)
		multicastif = argv[1];
	if((r = upnpc_init(&upnp, multicastif)) < 0) {
		fprintf(stderr, "upnpc_init failed : %d", r);
		return 1;
	}
	r = upnpc_process(&upnp);
	printf("upnpc_process returned %d\n", r);
	while(upnp.state != EError) {
		int nfds;
		fd_set readfds;
		fd_set writefds;
		/*struct timeval timeout;*/

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		nfds = 0;
		n = upnpc_select_fds(&upnp, &nfds, &readfds, &writefds);
		if(n <= 0) {
			printf("nothing to select()...\n");
			break;
		}
#if 0
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
#endif
#if DEBUG
		printf("select(%d, ...);\n", nfds+1);
#endif /* DEBUG */
		if(select(nfds+1, &readfds, &writefds, NULL, NULL/*&timeout*/) < 0) {
			perror("select");
			return 1;
		}
		upnpc_check_select_fds(&upnp, &readfds, &writefds);
		r = upnpc_process(&upnp);
#if DEBUG
		printf("upnpc_process returned %d\n", r);
#endif /* DEBUG */
		if(r < 0)
			break;
		if(upnp.state == EReady) {
			char * p;
			printf("Process UPnP IGD Method results : HTTP %d\n", upnp.device_list->http_response_code); /* XXX */
			if(upnp.device_list->http_response_code == 200) {
				switch(last_method) {
				case EGetExternalIP:
					p = GetValueFromNameValueList(&upnp.device_list->soap_response_data, "NewExternalIPAddress");
					printf("ExternalIPAddress = %s\n", p);
	/*				p = GetValueFromNameValueList(&pdata, "errorCode");*/
					break;
				case EGetRates:
					p = GetValueFromNameValueList(&upnp.device_list->soap_response_data, "NewLayer1DownstreamMaxBitRate");
					printf("DownStream MaxBitRate = %s\t", p);
					p = GetValueFromNameValueList(&upnp.device_list->soap_response_data, "NewLayer1UpstreamMaxBitRate");
					printf("UpStream MaxBitRate = %s\n", p);
					break;
				case EAddPortMapping:
					printf("OK\n");
					break;
				case ENothing:
					break;
				}
			} else {
				printf("SOAP error :\n");
				printf("  faultcode='%s'\n", GetValueFromNameValueList(&upnp.device_list->soap_response_data, "faultcode"));
				printf("  faultstring='%s'\n", GetValueFromNameValueList(&upnp.device_list->soap_response_data, "faultstring"));
				printf("  errorCode=%s\n", GetValueFromNameValueList(&upnp.device_list->soap_response_data, "errorCode"));
				printf("  errorDescription='%s'\n", GetValueFromNameValueList(&upnp.device_list->soap_response_data, "errorDescription"));
			}
			if(next_method_to_call == ENothing)
				break;
			printf("Ready to call UPnP IGD methods\n");
			last_method = next_method_to_call;
			switch(next_method_to_call) {
			case EGetExternalIP:
				printf("GetExternalIPAddress\n");
				upnpc_get_external_ip_address(upnp.device_list);
				next_method_to_call = EGetRates;
				break;
			case EGetRates:
				printf("GetCommonLinkProperties\n");
				upnpc_get_link_layer_max_rate(upnp.device_list);
				next_method_to_call = EAddPortMapping;
				break;
			case EAddPortMapping:
				if(getnameinfo((struct sockaddr *)&upnp.device_list->selfaddr, upnp.device_list->selfaddrlen,
				               ip_address, sizeof(ip_address), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV) < 0) {
					fprintf(stderr, "getnameinfo() failed\n");
				}
				printf("our IP address is %s\n", ip_address);
				printf("AddPortMapping\n");
				upnpc_add_port_mapping(upnp.device_list,	/* XXX */
                           NULL /* remote_host */, 40002 /* ext_port */,
                           42042 /* int_port */, ip_address /* int_client */,
                           "TCP" /* proto */, "this is a test" /* description */,
                           0 /* lease duration */);
				next_method_to_call = ENothing;
			case ENothing:
				break;
			}
		}
	}
	upnpc_finalize(&upnp);
	return 0;
}

