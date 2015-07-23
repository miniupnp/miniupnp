/* $Id: minissdpc.h,v 1.1 2007/08/31 15:15:33 nanard Exp $ */
/* Project: miniupnp
 * http://miniupnp.free.fr/ or http://miniupnp.tuxfamily.org/
 * Author: Thomas Bernard
 * Copyright (c) 2005-2007 Thomas Bernard
 * This software is subjects to the conditions detailed
 * in the LICENCE file provided within this distribution */
#ifndef MINISSDPC_H_INCLUDED
#define MINISSDPC_H_INCLUDED

#include "miniupnpc_declspec.h"

/* error codes : */
#define MINISSDPC_SUCCESS (0)
#define MINISSDPC_SOCKET_ERROR (-101)
#define MINISSDPC_INVALID_INPUT (-103)

#ifdef __cplusplus
extern "C" {
#endif

MINIUPNP_LIBSPEC struct UPNPDev *
getDevicesFromMiniSSDPD(const char * devtype, const char * socketpath, int * error);

MINIUPNP_LIBSPEC int
connectToMiniSSDPD(const char * socketpath);

MINIUPNP_LIBSPEC int
disconnectFromMiniSSDPD(int fd);

MINIUPNP_LIBSPEC int
requestDevicesFromMiniSSDPD(int fd, const char * devtype);

MINIUPNP_LIBSPEC struct UPNPDev *
receiveDevicesFromMiniSSDPD(int fd, int * error);

#ifdef __cplusplus
}
#endif

#endif

