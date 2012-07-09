#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([minissdpd], [1.2], [https://github.com/miniupnp/miniupnp])
AC_CONFIG_SRCDIR([codelength.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Wportability tar-pax no-dist-gzip dist-xz subdir-objects parallel-tests])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
# Checks for programs.
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

AC_ARG_ENABLE([ipv6],AS_HELP_STRING([--disable-ipv6], [Disable IPv6]))

AS_IF([test "x$enable_ipv6" != "xno"], [
  AC_DEFINE([ENABLE_IPV6], [1], [Build with ipv6 support])
])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memset select socket strncasecmp strtoul daemon])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
