/* $Id: miniwget.h,v 1.14 2025/02/08 23:15:17 nanard Exp $ */
/* Project : miniupnp
 * Author : Thomas Bernard
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * Copyright (c) 2005-2025 Thomas Bernard
 * This software is subject to the conditions detailed in the
 * LICENCE file provided in this distribution.
 * */
#ifndef MINIWGET_H_INCLUDED
#define MINIWGET_H_INCLUDED

/*! \file miniwget.h
 * \brief Lightweight HTTP client API
 */
#include "miniupnpc_declspec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief perform HTTP GET on an URL
 *
 * \param[in] url HTTP URL to GET
 * \param[out] size length of the returned buffer. -1 in case of memory
 *             allocation error
 * \param[in] scope_id interface id for IPv6 to use if not specified in the URL
 * \param[out] status_code HTTP response status code (200, 404, etc.)
 * \return the body of the HTTP response
 */
MINIUPNP_LIBSPEC void * miniwget(const char * url, int * size,
                                 unsigned int scope_id, int * status_code);

/*! \brief perform HTTP GET on an URL
 *
 * Also get the local address used to reach the HTTP server
 *
 * \param[in] url HTTP URL to GET
 * \param[out] size length of the returned buffer. -1 in case of memory
 *             allocation error
 * \param[out] addr local address used to connect to the server
 * \param[in] addrlen size of the addr buffer
 * \param[in] scope_id interface id for IPv6 to use if not specified in the URL
 * \param[out] status_code HTTP response status code (200, 404, etc.)
 * \return the body of the HTTP response
 */
MINIUPNP_LIBSPEC void * miniwget_getaddr(const char * url, int * size,
                                         char * addr, int addrlen,
                                         unsigned int scope_id, int * status_code);

/*! \brief parse a HTTP URL
 *
 * URL formats supported :
 * - `http://192.168.1.1/path/xxx`
 * - `http://192.168.1.1:8080/path/xxx`
 * - `http://[2a00:1234:5678:90ab::123]/path/xxx`
 * - `http://[2a00:1234:5678:90ab::123]:8080/path/xxx`
 * - `http://[fe80::1234:5678:90ab%%eth0]/path/xxx`
 * - `http://[fe80::1234:5678:90ab%%eth0]:8080/path/xxx`
 *
 * `%` may be encoded as `%25`
 *
 * \todo should probably not be exposed in the public API
 * \param[in] url URL to parse
 * \param[out] hostname hostname part of the URL (size of MAXHOSTNAMELEN+1)
 * \param[out] port set to the port specified in the URL or 80
 * \param[out] path set to the begining of the path part of the URL
 * \param[out] scope_id set to the interface id if specified in the
 *             link-local IPv6 address
 * \return 0 for failure, 1 for success
 */
int parseURL(const char * url,
             char * hostname, unsigned short * port, char * * path,
             unsigned int * scope_id);

#ifdef __cplusplus
}
#endif

#endif
