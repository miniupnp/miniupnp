#pragma once

#ifdef _MSC_VER
#define ISINVALID(s) (INVALID_SOCKET==(s))
#else
typedef SOCKET int
typedef SSIZE_T ssize_t
#define INVALID_SOCKET (-1)
#define ISINVALID(s) (0>(s))
#endif