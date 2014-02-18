/* $Id: $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * (c) 2006-2014 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#ifndef ASYNCSENDTO_H_INCLUDED
#define ASYNCSENDTO_H_INCLUDED

ssize_t
sendto_schedule(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen,
                unsigned int delay);

ssize_t
sendto_or_schedule(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);

int get_next_scheduled_send(struct timeval * next_send);

int try_sendto(fd_set * writefds);

int get_sendto_fds(fd_set * writefds, int * max_fd, const struct timeval * now);

#endif
