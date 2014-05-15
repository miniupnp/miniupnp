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
#include "upnputils.h"

/* state diagram for a packet :
 *
 *                     |
 *                     V
 * -> ESCHEDULED -> ESENDNOW -> sent
 *                    ^  |
 *                    |  V
 *                EWAITREADY -> sent
 */
struct scheduled_send {
	LIST_ENTRY(scheduled_send) entries;
	struct timeval ts;
	enum {ESCHEDULED=1, EWAITREADY=2, ESENDNOW=3} state;
	int sockfd;
	size_t len;
	int flags;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dest_addr;
	char buf[];
};

static LIST_HEAD(listhead, scheduled_send) send_list = { NULL };

/* TODO: Consider if this _sa_len fallback is good. In practise, many
 * APIs do not care about sa_len being set so perhaps this 'be nice in
 * what we receive' is good behavior. */
#define SA_OR_NULL_LEN(sa) ((sa) ? SA_LEN(sa) ? SA_LEN(sa) : _sa_len(sa) : 0)

static size_t send_from_to(int sockfd, const void *buf, size_t len, int flags,
			   const struct sockaddr *src_addr,
			   const struct sockaddr *dest_addr)
{
	struct iovec iov;
	struct in6_pktinfo ipi6;
	uint8_t c[CMSG_SPACE(sizeof(ipi6))];
	struct msghdr msg;

	iov.iov_base = (void *)buf; /* sendmsg won't write here anyway */
	iov.iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (src_addr && src_addr->sa_family == AF_INET) {
		/* TODO - write when needed, but as long as sockets
		 * are bound per IP, there's no need.  */
	} else if (src_addr && src_addr->sa_family == AF_INET6) {
		struct cmsghdr* cmsg;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)src_addr;

		ipi6.ipi6_addr = sin6->sin6_addr;
		ipi6.ipi6_ifindex = sin6->sin6_scope_id;
		msg.msg_control = c;
		msg.msg_controllen = sizeof(c);
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(ipi6));
		*((struct in6_pktinfo *)CMSG_DATA(cmsg)) = ipi6;
	} else {
	}
	msg.msg_name = (void *)dest_addr;/* sendmsg won't write here anyway */
	msg.msg_namelen = SA_OR_NULL_LEN(dest_addr);
	return sendmsg(sockfd, &msg, flags);
}


/* delay = milli seconds */
ssize_t
send_schedule(int sockfd, const void *buf, size_t len, int flags,
	      const struct sockaddr *src_addr, const struct sockaddr *dest_addr,
	      unsigned int delay)
{
	enum {ESCHEDULED, EWAITREADY, ESENDNOW} state;
	ssize_t n;
	struct timeval tv;
	struct scheduled_send * elt;

	if(delay == 0) {
		/* first try to send at once */
		n = send_from_to(sockfd, buf, len, flags, src_addr, dest_addr);
		if(n >= 0)
			return n;
		else if(errno == EAGAIN || errno == EWOULDBLOCK) {
			/* use select() on this socket */
			state = EWAITREADY;
		} else if(errno == EINTR) {
			state = ESENDNOW;
		} else {
			/* uncatched error */
			return n;
		}
	} else {
		state = ESCHEDULED;
	}

	/* schedule */
	if(gettimeofday(&tv, 0) < 0) {
		return -1;
	}
	/* allocate enough space for structure + buffers */
	elt = malloc(sizeof(struct scheduled_send) + len);
	if(elt == NULL) {
		syslog(LOG_ERR, "malloc failed to allocate %u bytes",
		       (unsigned)(sizeof(struct scheduled_send) + len));
		return -1;
	}
	elt->state = state;
	/* time the packet should be sent */
	elt->ts.tv_sec = tv.tv_sec + (delay / 1000);
	elt->ts.tv_usec = tv.tv_usec + (delay % 1000) * 1000;
	if(elt->ts.tv_usec > 1000000) {
		elt->ts.tv_sec++;
		elt->ts.tv_usec -= 1000000;
	}
	elt->sockfd = sockfd;
	elt->flags = flags;
	memset(&elt->src_addr, 0, sizeof(elt->src_addr));
	memcpy(&elt->src_addr, src_addr, SA_OR_NULL_LEN(src_addr));
	memset(&elt->dest_addr, 0, sizeof(elt->dest_addr));
	memcpy(&elt->dest_addr, dest_addr, SA_OR_NULL_LEN(dest_addr));
	memcpy(elt->buf, buf, len);
	elt->len = len;
	/* insert */
	LIST_INSERT_HEAD( &send_list, elt, entries);
	return 0;
}


/* try to send at once, and queue the packet if needed */
ssize_t
send_or_schedule(int sockfd, const void *buf, size_t len, int flags,
		 const struct sockaddr *src_addr,
		 const struct sockaddr *dest_addr)
{
	return send_schedule(sockfd, buf, len, flags, src_addr, dest_addr, 0);
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

/* update writefds for select() call
 * return the number of packets to try to send at once */
int get_send_fds(fd_set * writefds, int * max_fd, const struct timeval * now)
{
	int n = 0;
	struct scheduled_send * elt;
	for(elt = send_list.lh_first; elt != NULL; elt = elt->entries.le_next) {
		if(elt->state == EWAITREADY) {
			/* last sendmsg() call returned EAGAIN/EWOULDBLOCK */
			FD_SET(elt->sockfd, writefds);
			if(elt->sockfd > *max_fd)
				*max_fd = elt->sockfd;
			n++;
		} else if((elt->ts.tv_sec < now->tv_sec) ||
		          (elt->ts.tv_sec == now->tv_sec && elt->ts.tv_usec <= now->tv_usec)) {
			/* we waited long enough, now send ! */
			elt->state = ESENDNOW;
			n++;
		}
	}
	return n;
}

/* executed sendmsg() when needed */
int try_send(fd_set * writefds)
{
	int ret = 0;
	ssize_t n;
	struct scheduled_send * elt;
	struct scheduled_send * next;
	for(elt = send_list.lh_first; elt != NULL; elt = next) {
		next = elt->entries.le_next;
		if((elt->state == ESENDNOW) ||
		   (elt->state == EWAITREADY && FD_ISSET(elt->sockfd, writefds))) {
			syslog(LOG_DEBUG, "%s: %d bytes on socket %d",
			       "try_send", (int)elt->len, elt->sockfd);
			n = send_from_to(elt->sockfd, elt->buf, elt->len,
					 elt->flags,
					 (struct sockaddr *)&elt->src_addr,
					 (struct sockaddr *)&elt->dest_addr);
			if(n < 0) {
				if(errno == EINTR) {
					/* retry at once */
					elt->state = ESENDNOW;
					continue;
				} else if(errno == EAGAIN || errno == EWOULDBLOCK) {
					/* retry once the socket is ready for writing */
					elt->state = EWAITREADY;
					continue;
				} else {
					char addr_str[64];
					/* uncatched error */
					if(sockaddr_to_string((struct sockaddr *)&elt->dest_addr, addr_str, sizeof(addr_str)) <= 0)
						addr_str[0] = '\0';
					syslog(LOG_ERR, "%s(sock=%d, len=%u, dest=%s): sendmsg: %m",
					       "try_send", elt->sockfd, (unsigned)elt->len,
					       addr_str);
					ret--;
				}
			} else if((int)n != (int)elt->len) {
				syslog(LOG_WARNING, "%s: %d bytes sent out of %d",
				       "try_send", (int)n, (int)elt->len);
			}
			/* remove from the list */
			LIST_REMOVE(elt, entries);
			free(elt);
		}
	}
	return ret;
}

/* maximum execution time for finalize_send() in milliseconds */
#define FINALIZE_SEND_DELAY	(500)

/* empty the list */
void finalize_send(void)
{
	ssize_t n;
	struct scheduled_send * elt;
	struct scheduled_send * next;
	fd_set writefds;
	struct timeval deadline;
	struct timeval now;
	struct timeval timeout;
	int max_fd;

	if(gettimeofday(&deadline, NULL) < 0) {
		syslog(LOG_ERR, "gettimeofday: %m");
		return;
	}
	deadline.tv_usec += FINALIZE_SEND_DELAY*1000;
	if(deadline.tv_usec > 1000000) {
		deadline.tv_sec++;
		deadline.tv_usec -= 1000000;
	}
	while(send_list.lh_first) {
		FD_ZERO(&writefds);
		max_fd = -1;
		for(elt = send_list.lh_first; elt != NULL; elt = next) {
			next = elt->entries.le_next;
			syslog(LOG_DEBUG, "finalize_send(): %d bytes on socket %d",
			       (int)elt->len, elt->sockfd);
			n = send_from_to(elt->sockfd, elt->buf, elt->len,
					 elt->flags,
					 (struct sockaddr *)&elt->src_addr,
					 (struct sockaddr *)&elt->dest_addr);
			if(n < 0) {
				if(errno==EAGAIN || errno==EWOULDBLOCK) {
					FD_SET(elt->sockfd, &writefds);
					if(elt->sockfd > max_fd)
						max_fd = elt->sockfd;
					continue;
				}
				syslog(LOG_WARNING, "finalize_send(): socket=%d sendmsg: %m", elt->sockfd);
			}
			/* remove from the list */
			LIST_REMOVE(elt, entries);
			free(elt);
		}
		/* check deadline */
		if(gettimeofday(&now, NULL) < 0) {
			syslog(LOG_ERR, "gettimeofday: %m");
			return;
		}
		if(now.tv_sec > deadline.tv_sec ||
		   (now.tv_sec == deadline.tv_sec && now.tv_usec > deadline.tv_usec)) {
			/* deadline ! */
			while((elt = send_list.lh_first) != NULL) {
				LIST_REMOVE(elt, entries);
				free(elt);
			}
			return;
		}
		/* compute timeout value */
		timeout.tv_sec = deadline.tv_sec - now.tv_sec;
		timeout.tv_usec = deadline.tv_usec - now.tv_usec;
		if(timeout.tv_usec < 0) {
			timeout.tv_sec--;
			timeout.tv_usec += 1000000;
		}
		if(max_fd >= 0) {
			if(select(max_fd + 1, NULL, &writefds, NULL, &timeout) < 0) {
				syslog(LOG_ERR, "select: %m");
				return;
			}
		}
	}
}

