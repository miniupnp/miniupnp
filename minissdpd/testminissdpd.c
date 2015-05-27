/* $Id: testminissdpd.c,v 1.8 2014/02/28 18:38:21 nanard Exp $ */
/* Project : miniupnp
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2014 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */
#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DECODELENGTH(n, p) n = 0; \
                           do { n = (n << 7) | (*p & 0x7f); } \
                           while(*(p++)&0x80);

void printresponse(const unsigned char * resp, int n)
{
	int i, l;
	unsigned int nresp;
	const unsigned char * p;
	if(n == 0)
		return;
	for(i=0; i<n; i++)
		printf("%02x ", resp[i]);
	printf("\n");
	nresp = resp[0];
	p = resp + 1;
	for(i = 0; i < (int)nresp; i++) {
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("%d - %.*s\n", i, l, p);
		p += l;
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("    %.*s\n", l, p);
		p += l;
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("    %.*s\n", l, p);
		p += l;
	}
	return;
error:
	printf("*** WARNING : TRUNCATED RESPONSE ***\n");
}

#define SENDCOMMAND(command, size) write(s, command, size); \
              printf("Command written type=%u\n", (unsigned)command[0]);

int connect_unix_socket(const char * sockpath)
{
	int s;
	struct sockaddr_un addr;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if(connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		fprintf(stderr, "connecting to %s\n", addr.sun_path);
		perror("connect");
		exit(1);
	}
	printf("Connected.\n");
	return s;
}

/* test program for minissdpd */
int
main(int argc, char * * argv)
{
	char command1[] = "\x01\x00urn:schemas-upnp-org:device:InternetGatewayDevice";
	char command2[] = "\x02\x00uuid:fc4ec57e-b051-11db-88f8-0060085db3f6::upnp:rootdevice";
	char command3[] = { 0x03, 0x00 };
	char command4[] = "\x04\x00test:test:test";
	char bad_command[] = { 0xff, 0xff };
	char overflow[] = { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int s;
	int i;
	unsigned char buf[RESPONSE_BUFFER_SIZE];
    unsigned char chunk[4096];
	ssize_t n;
    int total = 0; 
	const char * sockpath = "/var/run/minissdpd.sock";

    printf("Response buffer size %d bytes\n", (int)RESPONSE_BUFFER_SIZE);

	for(i=0; i<argc-1; i++) {
		if(0==strcmp(argv[i], "-s"))
			sockpath = argv[++i];
	}
	command1[1] = sizeof(command1) - 3;
	command2[1] = sizeof(command2) - 3;
	command4[1] = sizeof(command4) - 3;
	s = connect_unix_socket(sockpath);

	SENDCOMMAND(command1, sizeof(command1) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	SENDCOMMAND(command2, sizeof(command2) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

    chunk[0] = 0; /* Slight hack for printing num devices when 0 */
	SENDCOMMAND(command3, sizeof(command3));
	n = read(s, chunk, sizeof(chunk));
	printf("Response received %d bytes\n", (int)n);
    printf("Number of devices %d\n", (int)chunk[0]);
    while (1) {
        if (n < (int)sizeof(chunk)) {
            if (n > 0) {
                memcpy(buf + total, chunk, n);
                total += n;
            }
            break;
        }

        memcpy(buf + total, chunk, n);
        total += n;
        n = read(s, chunk, sizeof(chunk));
        printf("response received %d bytes\n", (int)n);
    }
	printresponse(buf, total);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	SENDCOMMAND(command4, sizeof(command4));

	SENDCOMMAND(bad_command, sizeof(bad_command));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	SENDCOMMAND(overflow, sizeof(overflow));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);

	close(s);
	return 0;
}
