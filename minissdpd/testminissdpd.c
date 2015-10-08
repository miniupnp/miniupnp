/* $Id: testminissdpd.c,v 1.12 2015/08/06 13:16:59 nanard Exp $ */
/* Project : miniupnp
 * website : http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2015 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */

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

void printversion(const unsigned char * resp, int n)
{
	int l;
	const unsigned char * p;

	p = resp;
	DECODELENGTH(l, p);
	if(resp + n < p + l) {
		printf("get version error\n");
	}
	printf("MiniSSDPd version : %.*s\n", l, p);
}

void printresponse(const unsigned char * resp, int n)
{
	int i, l;
	unsigned int nresp;
	const unsigned char * p;
	if(n == 0)
		return;
	/* first, hexdump the response : */
	for(i = 0; i < n; i += 16) {
		printf("%06x | ", i);
		for(l = i; l < n && l < (i + 16); l++)
			printf("%02x ", resp[l]);
		while(l < (i + 16)) {
			printf("   ");
			l++;
		}
		printf("| ");
		for(l = i; l < n && l < (i + 16); l++)
			putchar((resp[l] >= ' ' && resp[l] < 128) ? resp[l] : '.');
		putchar('\n');
	}
	/* now parse and display all devices of response */
	nresp = resp[0]; /* 1st byte : number of devices in response */
	p = resp + 1;
	for(i = 0; i < (int)nresp; i++) {
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("%d - %.*s\n", i, l, p); /* URL */
		p += l;
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("    %.*s\n", l, p);	/* ST */
		p += l;
		if(p >= resp + n)
			goto error;
		/*l = *(p++);*/
		DECODELENGTH(l, p);
		if(p + l > resp + n)
			goto error;
		printf("    %.*s\n", l, p); /* USN */
		p += l;
	}
	return;
error:
	printf("*** WARNING : TRUNCATED RESPONSE ***\n");
}

#define SENDCOMMAND(command, size) write(s, command, size); \
              printf("Command written type=%u\n", (unsigned char)command[0]);

int connect_unix_socket(const char * sockpath)
{
	int s;
	struct sockaddr_un addr;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if(connect(s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
		fprintf(stderr, "connecting to %s : ", addr.sun_path);
		perror("connect");
		exit(1);
	}
	printf("Connected to %s\n", addr.sun_path);
	return s;
}

/* test program for minissdpd */
int
main(int argc, char * * argv)
{
	char command0[] = { 0x00, 0x00 };
	char command1[] = "\x01\x00urn:schemas-upnp-org:device:InternetGatewayDevice";
	char command2[] = "\x02\x00uuid:fc4ec57e-b051-11db-88f8-0060085db3f6::upnp:rootdevice";
	char command3[] = { 0x03, 0x00 };
	/* old versions of minissdpd would reject a command with
	 * a zero length string argument */
	char command3compat[] = "\x03\x00ssdp:all";
	char command4[] = "\x04\x00test:test:test";
	char bad_command[] = { 0xff, 0xff };
	char overflow[] = { 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int s;
	int i;
	void * tmp;
	unsigned char * resp = NULL;
	size_t respsize = 0;
	unsigned char buf[4096];
	ssize_t n;
	int total = 0;
	const char * sockpath = "/var/run/minissdpd.sock";

	for(i=0; i<argc-1; i++) {
		if(0==strcmp(argv[i], "-s"))
			sockpath = argv[++i];
	}
	command1[1] = sizeof(command1) - 3;
	command2[1] = sizeof(command2) - 3;
	command3compat[1] = sizeof(command3compat) - 3;
	command4[1] = sizeof(command4) - 3;
	s = connect_unix_socket(sockpath);

	n = SENDCOMMAND(command0, sizeof(command0));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	if(n > 0) {
		printversion(buf, n);
	} else {
		printf("Command 0 (get version) not supported\n");
		close(s);
		s = connect_unix_socket(sockpath);
	}

	n = SENDCOMMAND(command1, sizeof(command1) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	n = SENDCOMMAND(command2, sizeof(command2) - 1);
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	buf[0] = 0; /* Slight hack for printing num devices when 0 */
	n = SENDCOMMAND(command3, sizeof(command3));
	n = read(s, buf, sizeof(buf));
	if(n == 0) {
		printf("command3 failed, testing compatible one\n");
		close(s);
		s = connect_unix_socket(sockpath);
		n = SENDCOMMAND(command3compat, sizeof(command3compat) - 1);
		n = read(s, buf, sizeof(buf));
	}
	printf("Response received %d bytes\n", (int)n);
	printf("Number of devices %d\n", (int)buf[0]);
	while(n > 0) {
		tmp = realloc(resp, respsize + n);
		if(tmp == NULL) {
			fprintf(stderr, "memory allocation error\n");
			break;
		}
		resp = tmp;
		respsize += n;
		if (n > 0) {
			memcpy(resp + total, buf, n);
			total += n;
		}
		if (n < (ssize_t)sizeof(buf)) {
			break;
		}

		n = read(s, buf, sizeof(buf));
		printf("response received %d bytes\n", (int)n);
	}
	if(resp != NULL) {
		printresponse(resp, total);
		free(resp);
		resp = NULL;
	}
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	n = SENDCOMMAND(command4, sizeof(command4));
	/* no response for request type 4 */

	n = SENDCOMMAND(bad_command, sizeof(bad_command));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);
	if(n == 0) {
		close(s);
		s = connect_unix_socket(sockpath);
	}

	n = SENDCOMMAND(overflow, sizeof(overflow));
	n = read(s, buf, sizeof(buf));
	printf("Response received %d bytes\n", (int)n);
	printresponse(buf, n);

	close(s);
	return 0;
}
