/* $Id: upnperrors.h,v 1.7 2025/01/26 00:31:44 nanard Exp $ */
/* (c) 2007-2025 Thomas Bernard
 * All rights reserved.
 * MiniUPnP Project.
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subjet to the conditions detailed in the
 * provided LICENCE file. */
#ifndef UPNPERRORS_H_INCLUDED
#define UPNPERRORS_H_INCLUDED

/*! \file upnperrors.h
 * \brief code to string API for errors
 */
/*! \cond */
#include "miniupnpc_declspec.h"
/*! \endcond */

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \brief convert error code to string
 *
 * \param[in] err error code
 * \return a string description of the error code
 *         or NULL for undefinded errors
 */
MINIUPNP_LIBSPEC const char * strupnperror(int err);

#ifdef __cplusplus
}
#endif

#endif
