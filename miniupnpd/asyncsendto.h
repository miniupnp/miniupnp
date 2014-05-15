/* $Id: $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2014 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef ASYNCSENDTO_H_INCLUDED
#define ASYNCSENDTO_H_INCLUDED

/* send_schedule() : sendmsg(2), but with convenience arguments
 * schedule sendmsg() call after delay (milliseconds) */
ssize_t
send_schedule(int sockfd, const void *buf, size_t len, int flags,
              const struct sockaddr *src_addr,
              const struct sockaddr *dest_addr,
              unsigned int delay);

/* send_or_schedule() : sendmsg(2), but with convenience arguments
 * try sendmsg() at once and schedule if EINTR/EAGAIN/EWOULDBLOCK */
ssize_t
send_or_schedule(int sockfd, const void *buf, size_t len, int flags,
                 const struct sockaddr *src_addr,
                 const struct sockaddr *dest_addr);

/* get_next_scheduled_send()
 * return number of scheduled sends
 * set next_send to timestamp to send next packet */
int get_next_scheduled_send(struct timeval * next_send);

/* execute sendmsg() for needed packets */
int try_send(fd_set * writefds);

/* set writefds before select() */
int get_send_fds(fd_set * writefds, int * max_fd, const struct timeval * now);

/* empty the list */
void finalize_send(void);

#endif
