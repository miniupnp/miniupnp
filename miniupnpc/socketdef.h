#pragma once

#ifdef _MSC_VER
#define ISINVALID(s) (INVALID_SOCKET==(s))
#else
typedef SOCKET int;
typedef SSIZE_T ssize_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef ISINVALID
#define ISINVALID(s) (0>(s))
#endif
#endif