/* $Id: testminissdpd.c,v 1.7 2012/05/02 10:28:25 nanard Exp $ */
/* Project : miniupnp
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2007 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */
#include <unistd.h>
#include <stdio.h>
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
	for(i=0; i<n; i++)
		printf("%02x ", resp[i]);
	printf("\n");
	nresp = resp[0];
	p = resp + 1;
	for(i = 0; i < (int)nresp; i++) {
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		printf("%d - %.*s\n", i, l, p);
		p += l;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		printf("    %.*s\n", l, p);
		p += l;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		printf("    %.*s\n", l, p);
		p += l;
	}
}

#define SENDCOMMAND(command, size) write(s, command, size); \
              printf("Command written type=%u\n", (unsigned)command[0]);

/* test program for minissdpd */
int
main(int argc, char * * argv)
{
	char command1[] = "\x01\x00urn:schemas-upnp-org:device:InternetGatewayDevice";
	char command2[] = "\x02\x00uuid:fc4ec57e-b051-11db-88f8-0060085db3f6::upnp:rootdevice";
	char command3[] = { 0x03, 0x00 };
	struct sockaddr_un addr;
	int s;
	int i;
	unsigned char buf[2048];
	ssize_t n;
	const char * sockpath = "/var/run/minissdpd.sock";

	for(i=0; i<argc-1; i++) {
		if(0==strcmp(argv[i], "-s"))
			sockpath = argv[++i];
	}
	command1[1] = sizeof(command1) - 3;
	command2[1] = sizeof(command2) - 3;
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if(connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		fprintf(stderr, "connecting to %s\n", addr.sun_path);
		perror("connect");
		return 1;
	}
	printf("Connected.\n");

	SENDCOMMAND(command1, sizeof(command1) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);

	SENDCOMMAND(command2, sizeof(command2) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);

	SENDCOMMAND(command3, sizeof(command3));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);

	close(s);
	return 0;
}

