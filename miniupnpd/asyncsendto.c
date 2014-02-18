/* $Id: $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2014 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "asyncsendto.h"

struct scheduled_send {
	LIST_ENTRY(scheduled_send) entries;
	struct timeval ts;
	int sockfd;
	const void * buf;
	size_t len;
	int flags;
	const struct sockaddr *dest_addr;
	socklen_t addrlen;
	char data[];
};

static LIST_HEAD(listhead, scheduled_send) send_list = { NULL };

/*
 * ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
 *                const struct sockaddr *dest_addr, socklen_t addrlen);
 */

/* delay = milli seconds */
ssize_t
sendto_schedule(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen,
                unsigned int delay)
{
	ssize_t n;
	struct timeval tv;
	struct scheduled_send * elt;

	if(delay == 0) {
		/* first try to send at once */
		n = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
		if((n >= 0) || (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK))
			return n;
	}
	/* schedule */
	if(gettimeofday(&tv, 0) < 0) {
		return -1;
	}
	/* allocate enough space for structure + buffers */
	elt = malloc(sizeof(struct scheduled_send) + len + addrlen);
	if(elt == NULL) {
		syslog(LOG_ERR, "malloc failed to allocate %u bytes",
		       (unsigned)(sizeof(struct scheduled_send) + len + addrlen));
		return -1;
	}
	/* time the packet should be sent */
	elt->ts.tv_sec = tv.tv_sec + (delay / 1000);
	elt->ts.tv_usec = tv.tv_usec + (delay % 1000) * 1000;
	if(elt->ts.tv_usec > 1000000) {
		elt->ts.tv_sec++;
		elt->ts.tv_usec -= 1000000;
	}
	elt->sockfd = sockfd;
	elt->flags = flags;
	memcpy(elt->data, dest_addr, addrlen);
	elt->dest_addr = (struct sockaddr *)elt->data;
	elt->addrlen = addrlen;
	memcpy(elt->data + addrlen, buf, len);
	elt->buf = (void *)(elt->data + addrlen);
	elt->len = len;
	/* insert */
	LIST_INSERT_HEAD( &send_list, elt, entries);
	return 0;
}


ssize_t
sendto_or_schedule(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto_schedule(sockfd, buf, len, flags, dest_addr, addrlen, 0);
}

/* get_next_scheduled_send() return number of scheduled send in list */
int get_next_scheduled_send(struct timeval * next_send)
{
	int n = 0;
	struct scheduled_send * elt;
	if(next_send == NULL)
		return -1;
	for(elt = send_list.lh_first; elt != NULL; elt = elt->entries.le_next) {
		if(n == 0 || (elt->ts.tv_sec < next_send->tv_sec) ||
		   (elt->ts.tv_sec == next_send->tv_sec && elt->ts.tv_usec < next_send->tv_usec)) {
			next_send->tv_sec = elt->ts.tv_sec;
			next_send->tv_usec = elt->ts.tv_usec;
		}
		n++;
	}
	return n;
}

int get_sendto_fds(fd_set * writefds, int * max_fd, const struct timeval * now)
{
	int n = 0;
	struct scheduled_send * elt;
	for(elt = send_list.lh_first; elt != NULL; elt = elt->entries.le_next) {
		if((elt->ts.tv_sec < now->tv_sec) ||
		   (elt->ts.tv_sec == now->tv_sec && elt->ts.tv_usec <= now->tv_usec)) {
			FD_SET(elt->sockfd, writefds);
			if(elt->sockfd > *max_fd)
				*max_fd = elt->sockfd;
			n++;
		}
	}
syslog(LOG_DEBUG, "%x", (int)writefds->fds_bits[0]);
	return n;
}

int try_sendto(fd_set * writefds)
{
	ssize_t n;
	struct scheduled_send * elt;
	struct scheduled_send * next;
	for(elt = send_list.lh_first; elt != NULL; elt = next) {
		next = elt->entries.le_next;
syslog(LOG_DEBUG, "s=%d fds=%x", elt->sockfd, (int)writefds->fds_bits[0]);
		if(FD_ISSET(elt->sockfd, writefds)) {
			syslog(LOG_DEBUG, "sending %d bytes", (int)elt->len);
			n = sendto(elt->sockfd, elt->buf, elt->len, elt->flags,
			           elt->dest_addr, elt->addrlen);
			if(n < 0) {
				syslog(LOG_DEBUG, "sendto: %m");
				if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
					continue;
				return n;
			} else {
				LIST_REMOVE(elt, entries);
				free(elt);
			}
		}
	}
	return 0;
}

