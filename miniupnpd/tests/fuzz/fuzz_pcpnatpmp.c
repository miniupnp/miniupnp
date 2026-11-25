/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Fuzz target for PCP (RFC 6887, pcpserver.c) and NAT-PMP (RFC 6886,
 * natpmp.c) request processing.
 *
 * Input byte 0 selects the path:
 *   (b & 3) % 3 == 0 : NAT-PMP request from 192.168.1.100
 *                == 1 : PCP request from 192.168.1.100
 *                == 2 : PCP request from fd00::100
 *   b & 4            : allow_third_party (skips the LAN locality check)
 *   b & 8            : apply the permission rules set up in fuzz_stubs.c
 * The rest of the input is the UDP payload. Like miniupnpd.c, the payload
 * is copied into a PCP_MAX_LEN + 1 byte buffer, because the reply is built
 * in place in that buffer. Replies go to a stubbed sendto_or_schedule(). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "upnpglobalvars.h"
#include "natpmp.h"
#include "pcpserver.h"

void fuzz_init(void);
extern unsigned int fuzz_num_perm;

int LLVMFuzzerInitialize(int * argc, char * * * argv)
{
	(void)argc; (void)argv;
	fuzz_init();
	SETFLAG(ENABLENATPMPMASK);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
	unsigned char * msg_buff;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6, r6;
	int mode;

	if(size < 1)
		return 0;
	mode = (data[0] & 3) % 3;
	if(data[0] & 4)
		SETFLAG(PCP_ALLOWTHIRDPARTYMASK);
	else
		CLEARFLAG(PCP_ALLOWTHIRDPARTYMASK);
	/* With permission rules a denied MAP request scans many ports for an allowed one,
	 * which is slow, so the rules are enabled only when bit 3 is set. */
	num_upnpperm = (data[0] & 8) ? fuzz_num_perm : 0;
	data++;
	size--;
	if(size > PCP_MAX_LEN)
		size = PCP_MAX_LEN;
	msg_buff = calloc(1, PCP_MAX_LEN + 1);
	if(msg_buff == NULL)
		return 0;
	memcpy(msg_buff, data, size);

	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	s4.sin_port = htons(5351);
	inet_pton(AF_INET, "192.168.1.100", &s4.sin_addr);
	memset(&s6, 0, sizeof(s6));
	s6.sin6_family = AF_INET6;
	s6.sin6_port = htons(5351);
	inet_pton(AF_INET6, "fd00::100", &s6.sin6_addr);
	memset(&r6, 0, sizeof(r6));
	r6.sin6_family = AF_INET6;
	r6.sin6_port = htons(5351);
	inet_pton(AF_INET6, "fd00::1", &r6.sin6_addr);

	if(mode == 0)
		ProcessIncomingNATPMPPacket(3, msg_buff, (int)size, &s4);
	else if(mode == 1)
		ProcessIncomingPCPPacket(3, msg_buff, (int)size, (struct sockaddr *)&s4, NULL);
	else
		ProcessIncomingPCPPacket(4, msg_buff, (int)size, (struct sockaddr *)&s6, &r6);
	free(msg_buff);
	return 0;
}
