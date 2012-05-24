/*
 * Written by zephyrus00jp 
 *  UPNP-Proxy package
 *
 *  Copyright (C) 2009  zephyrus00jp
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *  (version 2) as published by the Free Software Foundation; either
 *   version 2 of the License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   To contact the author, post a message to a forum at
 *   http://upnpproxy.sourceforge.net 
 *
 *   (Or as a last resort, try zephyrus00jp@gmail.com The e-mail is not
 *   monitored all the time. )
 */

#include <stdio.h>

/* EXIT_SUCCESS */

#include <stdlib.h>

/*  gettimeofday() */
#include <sys/time.h>

/* usleep() */
#include <unistd.h>

/* nanosleep */
#include <time.h>

/* obsolete
 * extern int gettimeofday(struct timeval *tv, struct timezone *tz);
 */

/* should use
extern int nanosleep(const struct timespec *req, struct timespec *rem);
*/

/*
 * wait for 0.5 sec if nothing is given as argument.
 */
int
main(int argc, char *argv[])
{
  long itime = 500000;
  int rc;
  struct timespec req;
  struct timespec rem;

  if(argc <= 1)
    {
      fprintf(stderr,"Argument not given. Waiting for 0.5 sec.\n");
    }
  else
    {
      sscanf(argv[1], "%ld", &itime);
      fprintf(stdout, "%s:will wait for %ld microseconds.\n", argv[0], itime);
      if(itime < 0)
	{
	  fprintf(stderr, "wait period must not be negative.\n");
	  exit(EXIT_FAILURE);
	}
    }

  req.tv_sec = itime / 1000000;
  req.tv_nsec = itime * 1000 - req.tv_sec * 1000000000;

  rc = nanosleep(&req, &rem);

  if(rc != 0)
    fprintf(stderr,"nanosleep returned %d\n", rc);

  exit(EXIT_SUCCESS);
}
