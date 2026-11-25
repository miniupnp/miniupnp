/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Fuzz target for the HTTP and SOAP request handling of miniupnpd:
 * upnphttp.c (request parsing, chunked encoding, SUBSCRIBE/UNSUBSCRIBE),
 * upnpsoap.c (all IGD actions), upnpreplyparse.c and minixml.c.
 *
 * The input is the raw byte stream a LAN client sends to the HTTP port.
 * recv(), send() and close() are wrapped (-Wl,--wrap=...) so the real
 * Process_upnphttp() state machine reads the input from memory.
 * Firewall and OS back-ends are stubbed in fuzz_stubs.c. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"
#include "upnphttp.h"

#define FAKE_FD 1000
#define MAX_INPUT 60000

void fuzz_init(void);

static const uint8_t * in_data;
static size_t in_len, in_pos;
static size_t chunk;	/* if > 0, recv() returns at most chunk bytes */

ssize_t __real_recv(int, void *, size_t, int);
ssize_t __real_send(int, const void *, size_t, int);
int __real_close(int);

ssize_t __wrap_recv(int fd, void * buf, size_t len, int flags)
{
	size_t n;
	if(fd != FAKE_FD)
		return __real_recv(fd, buf, len, flags);
	n = in_len - in_pos;
	if(n > len)
		n = len;
	if(chunk && n > chunk)
		n = chunk;
	memcpy(buf, in_data + in_pos, n);
	in_pos += n;
	return (ssize_t)n;
}

ssize_t __wrap_send(int fd, const void * buf, size_t len, int flags)
{
	if(fd != FAKE_FD)
		return __real_send(fd, buf, len, flags);
	if(getenv("FUZZ_DEBUG"))
		fwrite(buf, 1, len, stderr);
	return (ssize_t)len;
}

int __wrap_close(int fd)
{
	return (fd == FAKE_FD) ? 0 : __real_close(fd);
}

int LLVMFuzzerInitialize(int * argc, char * * * argv)
{
	const char * c = getenv("FUZZ_CHUNK");
	(void)argc; (void)argv;
	fuzz_init();
	if(c)
		chunk = (size_t)atoi(c);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
	struct upnphttp * h;
	int i;

	if(size > MAX_INPUT)
		size = MAX_INPUT;
	in_data = data;
	in_len = size;
	in_pos = 0;
	h = New_upnphttp(FAKE_FD);
	if(h == NULL)
		return 0;
	inet_pton(AF_INET, "192.168.1.100", &h->clientaddr);
	strcpy(h->clientaddr_str, "192.168.1.100");
	for(i = 0; i < 4096 && h->state < EToDelete; i++)
		Process_upnphttp(h);
	Delete_upnphttp(h);
	return 0;
}
