#pragma once

#ifdef _MSC_VER
#define ISINVALID(s) (INVALID_SOCKET==(s))
#else
#ifndef
#define SOCKET int
#endif
#ifndef
#define SSIZE_T ssize_t
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef ISINVALID
#define ISINVALID(s) (0>(s))
#endif
#endif