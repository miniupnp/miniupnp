# MiniUPnP IGD client changelog

## [Unreleased]

## [2.2.6] - 2024-04-01

*2024-01-04*
- Includes charset="utf-8" in Content-Type
- Fix memory allocation error in minissdpc.c

*2023-06-15*
- Make User-Agent compliant.
- listdevices => upnp-listdevices

## [2.2.5] - 2023-06-12

*2023-06-05*
- GetListOfPortMappings NewStartPort 0 => 1

*2023-05-30*
- CheckPinholeWorking is optional
- Add 60x errors from UPnP Device Architecture

*2023-01-04*
- cmake: install binaries, man pages and external-ip.sh

## [2.2.4] - 2022-10-21

*2022-02-20*
- upnpc: use of @ to replace local lan address

*2021-11-09*
- python module: Allow to specify the root description url

## [2.2.3] - 2021-09-28

*2021-08-13*
- Change directory structure: include/ and src/ directories.

## [2.2.2] - 2021-03-03

*2021-01-15*
- miniupnpcmodule.c: throw an exception in UPnP_discover()

*2020-12-30*
- Fix usage of IP_MULTICAST_IF with struct ip_mreqn

## [2.2.1] - 2020-12-20

*2020-11-30*
- Add miniupnpc.rc for .dll description

## [2.2.0] - 2020-11-09

*2020-09-24*
- Check properly for reserved IP addresses

*2020-09-23*
- Prevent infinite loop in upnpDiscover()

*2020-02-16*
- Add Haiku support

*2019-10-22*
- testminiwget.sh can use either "ip addr" or "ifconfig -a

*2019-10-13*
- Fix UPNP_GetValidIGD() when several devices are found
  which are reachable from != local address

*2019-08-24*
- Allow Remote Host on upnpc command line
- Fix error 708 description in strupnperror()

*2019-04-05*
- Fix memory leak in upnpreplyparse.c with NewPortListing element

*2019-03-10*
- connecthostport.c: Code simplification, error trace fix

*2019-01-23*
- Set timeout for select() in connecthostport()

*2018-10-31*
- miniupnpcmodule.c: check return of WSAStartup()

*2018-07-14*
- Fix and improve MSVC project:
  - Add Dll configurations
  - Improve genminiupnpcstrings.vbs

*2018-06-18*
- Fixes for windows 64-bits.

## 2.1 - 2018-05-07

*2018-05-07*
- CMake Modernize and cleanup CMakeLists.txt
- Update MS Visual Studio projects

*2018-04-30*
- listdevices: show devices sorted by XML desc URL

*2018-04-26*
- Small fix in miniupnpcmodule.c (python module)
- Support cross compiling in Makefile.mingw

*2018-04-06*
- Use SOCKET type instead of int (for Win64 compilation)
- Increments API_VERSION to 17

*2018-02-22*
- Disable usage of MiniSSDPd when using -m option

*2017-12-11*
- Fix buffer over run in minixml.c
- Fix uninitialized variable access in upnpreplyparse.c

*2017-05-05*
- Fix CVE-2017-8798 Thanks to tin/Team OSTStrom

*2016-11-11*
- Check strlen before memcmp in XML parsing portlistingparse.c
- Fix build under SOLARIS and CYGWIN

*2016-10-11*
- Add python 3 compatibility to IGD test

## 2.0 - 2016-04-19

*2016-01-24*
- Change miniwget to return HTTP status code
- Increments API_VERSION to 16

*2016-01-22*
- Improve UPNPIGD_IsConnected() to check if WAN address is not private.
- Parse HTTP response status line in miniwget.c

*2015-10-26*
- snprintf() overflow check. check overflow in simpleUPnPcommand2()

*2015-10-25*
- Fix compilation with old macs
- Fix compilation with mingw32 (for Appveyor)
- Fix python module for python <= 2.3

*2015-10-08*
- Change sameport to localport
  See https://github.com/miniupnp/miniupnp/pull/120
- Increments API_VERSION to 15

*2015-09-15*
- Fix buffer overflow in igd_desc_parse.c/IGDstartelt()
  Discovered by Aleksandar Nikolic of Cisco Talos

*2015-08-28*
- Move ssdpDiscoverDevices() to minissdpc.c

*2015-08-27*
- Avoid unix socket leak in getDevicesFromMiniSSDPD()

*2015-08-16*
- Also accept "Up" as ConnectionStatus value

*2015-07-23*
- Split getDevicesFromMiniSSDPD
- Add ttl argument to upnpDiscover() functions
- Increments API_VERSION to 14

*2015-07-22*
- Read USN from SSDP messages.

*2015-07-15*
- Check malloc/calloc

*2015-06-16*
- Update getDevicesFromMiniSSDPD() to process longer minissdpd
  responses

*2015-05-22*
- Add searchalltypes param to upnpDiscoverDevices()
- Increments API_VERSION to 13

*2015-04-30*
- upnpc: output version on the terminal

*2015-04-27*
- _BSD_SOURCE is deprecated in favor of _DEFAULT_SOURCE
- Fix CMakeLists.txt COMPILE_DEFINITIONS
- Fix getDevicesFromMiniSSDPD() not setting scope_id
- Improve -r command of upnpc command line tool

*2014-11-17*
- Search all:
  upnpDiscoverDevices() / upnpDiscoverAll() functions
- listdevices executable
- Increment API_VERSION to 12
- Validate igd_desc_parse

*2014-11-13*
- Increment API_VERSION to 11

*2014-11-05*
- Simplified function GetUPNPUrls()

*2014-09-11*
- Use remoteHost arg of DeletePortMapping

*2014-09-06*
- Fix python3 build

*2014-07-01*
- Fix parsing of IGD2 root descriptions

*2014-06-10*
- Rename LIBSPEC to MINIUPNP_LIBSPEC

*2014-05-15*
- Add support for IGD2 AddAnyPortMapping and DeletePortMappingRange

*2014-02-05*
- Handle EINPROGRESS after connect()

*2014-02-03*
- minixml now handle XML comments

## 1.9 - 2014-01-31

*2014-01-31*
- Added argument remoteHost to UPNP_GetSpecificPortMappingEntry()
- Increment API_VERSION to 10

*2013-12-09*
- --help and -h arguments in upnpc.c

*2013-10-07*
- Fixed potential buffer overrun in miniwget.c
- Modified UPNP_GetValidIGD() to check for ExternalIpAddress

*2013-08-01*
- Define MAXHOSTNAMELEN if not already done

*2013-06-06*
- Update upnpreplyparse to allow larger values (128 chars instead of 64)

*2013-05-14*
- Update upnpreplyparse to take into account "empty" elements
- Validate upnpreplyparse.c code with "make check"

*2013-05-03*
- Fix Solaris build thanks to Maciej Małecki

*2013-04-27*
- Fix testminiwget.sh for BSD

*2013-03-23*
- Fixed Makefile for *BSD

*2013-03-11*
- Update Makefile to use JNAerator version 0.11

*2013-02-11*
- Fix testminiwget.sh for use with dash
- Use $(DESTDIR) in Makefile

## 1.8 - 2013-02-06

*2012-10-16*
- Fix testminiwget with no IPv6 support

*2012-09-27*
- Rename all include guards to not clash with C99
  (7.1.3 Reserved identifiers).

*2012-08-30*
- Added -e option to upnpc program (set description for port mappings)

*2012-08-29*
- Python 3 support (thanks to Christopher Foo)

*2012-08-11*
- Fix a memory link in UPNP_GetValidIGD()
- Try to handle scope id in link local IPv6 URL under MS Windows

*2012-07-20*
- Disable HAS_IP_MREQN on DragonFly BSD

*2012-06-28*
- GetUPNPUrls() now inserts scope into link-local IPv6 addresses

*2012-06-23*
- More error return checks in upnpc.c
- #define MINIUPNPC_GET_SRC_ADDR enables receivedata() to get scope_id
- parseURL() now parses IPv6 addresses scope
- New parameter for miniwget(): IPv6 address scope
- Increment API_VERSION to 9

*2012-06-20*
- Fixed CMakeLists.txt

*2012-05-29*
- Improvements in testminiwget.sh

## 1.7 - 2012-05-24

*2012-05-01*
- Cleanup settings of CFLAGS in Makefile
- Fix signed/unsigned integer comparaisons

*2012-04-20*
- Allow to specify protocol with TCP or UDP for -A option

*2012-04-09*
- Only try to fetch XML description once in UPNP_GetValidIGD()
- Added -ansi flag to compilation, and fixed C++ comments to ANSI C comments.

*2012-04-05*
- Minor improvements to minihttptestserver.c

*2012-03-15*
- upnperrors.c returns valid error string for unrecognized error codes

*2012-03-08*
- Make minihttptestserver listen on loopback interface instead of 0.0.0.0

*2012-01-25*
- Maven installation thanks to Alexey Kuznetsov

*2012-01-21*
- Replace WIN32 macro by _WIN32

*2012-01-19*
- Fixes in java wrappers thanks to Alexey Kuznetsov:
  https://github.com/axet/miniupnp/tree/fix-javatest/miniupnpc
- Make and install .deb packages (python) thanks to Alexey Kuznetsov:
  https://github.com/axet/miniupnp/tree/feature-debbuild/miniupnpc

*2012-01-07*
- The multicast interface can now be specified by name with IPv4.

*2012-01-02*
- Install man page

*2011-11-25*
- Added header to Port Mappings list in upnpc.c

*2011-10-09*
- Makefile: make clean now removes jnaerator generated files.
- MINIUPNPC_VERSION in miniupnpc.h (updated by make)

*2011-09-12*
- Added rootdescURL to UPNPUrls structure.

## 1.6 - 2011-07-25

*2011-07-25*
- Update doc for version 1.6 release

*2011-06-18*
- Fix for windows in miniwget.c

*2011-06-04*
- Display remote host in port mapping listing

*2011-06-03*
- Fix in make install: there were missing headers

*2011-05-26*
- Fix the socket leak in miniwget thanks to Richard Marsh.
- Permit to add leaseduration in -a command. Display lease duration.

*2011-05-15*
- Try both LinkLocal and SiteLocal multicast address for SSDP in IPv6

*2011-05-09*
- add a test in testminiwget.sh.
- more error checking in miniwget.c

*2011-05-06*
- Adding some tool to test and validate miniwget.c
- Simplified and debugged miniwget.c

*2011-04-11*
- Moving ReceiveData() to a receivedata.c file.
- Parsing presentation url
- Adding IGD v2 WANIPv6FirewallControl commands

*2011-04-10*
- Update of miniupnpcmodule.c
- Comments in miniwget.c, update in testminiwget
- Adding errors codes from IGD v2
- New functions in upnpc.c for IGD v2

*2011-04-09*
- Support for litteral ip v6 address in miniwget

*2011-04-08*
- Adding support for urn:schemas-upnp-org:service:WANIPv6FirewallControl:1
- Updating APIVERSION
- Supporting IPV6 in upnpDiscover()
- Adding a -6 option to upnpc command line tool

*2011-03-18*
- miniwget/parseURL(): return an error when url param is null.
- Fixing GetListOfPortMappings()

*2011-03-14*
- upnpDiscover() now reporting an error code.
- Improvements in comments.

*2011-03-11*
- Adding miniupnpcstrings.h.cmake and CMakeLists.txt files.

*2011-02-15*
- Implementation of GetListOfPortMappings()

*2011-02-07*
- Updates to minixml to support character data starting with spaces
- minixml now support CDATA
- upnpreplyparse treats <NewPortListing> specificaly
- Change in simpleUPnPcommand to return the buffer (simplification)

*2011-02-06*
- Added leaseDuration argument to AddPortMapping()
- Starting to implement GetListOfPortMappings()

*2011-01-11*
- Updating wingenminiupnpcstrings.c

*2011-01-04*
- Improving updateminiupnpcstrings.sh

## 1.5 - 2011-01-01

*2010-12-21*
- Use NO_GETADDRINFO macro to disable the use of getaddrinfo/freeaddrinfo

*2010-12-11*
- Improvements on getHTTPResponse() code.

*2010-12-09*
- New code for miniwget that handle Chunked transfer encoding
- Using getHTTPResponse() in SOAP call code
- Adding MANIFEST.in for 'python setup.py bdist_rpm'

*2010-11-25*
- Changes to minissdpc.c to compile under Win32.
  see http://miniupnp.tuxfamily.org/forum/viewtopic.php?t=729

*2010-09-17*
- Various improvement to Makefile from Michał Górny

*2010-08-05*
- Adding the script "external-ip.sh" from Reuben Hawkins

*2010-06-09*
- Update to python module to match modification made on 2010-04-05
- Update to Java test code to match modification made on 2010-04-05
- All UPNP_* function now return an error if the SOAP request failed
  at HTTP level.

*2010-04-17*
- Using GetBestRoute() under win32 in order to find the
  right interface to use.

*2010-04-12*
- Retrying with HTTP/1.1 if HTTP/1.0 failed. see
  http://miniupnp.tuxfamily.org/forum/viewtopic.php?p=1703

*2010-04-07*
- Avoid returning duplicates in upnpDiscover()

*2010-04-05*
- Create a connecthostport.h/.c with connecthostport() function
  and use it in miniwget and miniupnpc.
- Use getnameinfo() instead of inet_ntop or inet_ntoa
- Work to make miniupnpc IPV6 compatible...
- Add java test code.
- Big changes in order to support device having both WANIPConnection
  and WANPPPConnection.

*2010-04-04*
- Use getaddrinfo() instead of gethostbyname() in miniwget.

*2010-01-06*
- #define _DARWIN_C_SOURCE for Mac OS X

*2009-12-19*
- Improve MinGW32 build

*2009-12-11*
- Adding a MSVC9 project to build the static library and executable

*2009-12-10*
- Fixing some compilation stuff for Windows/MinGW

*2009-12-07*
- Adaptations in Makefile and updateminiupnpcstring.sh for AmigaOS
- Some fixes for Windows when using virtual ethernet adapters (it is the
  case with VMWare installed).

*2009-12-04*
- Some fixes for AmigaOS compilation
- Changed HTTP version to HTTP/1.0 for Soap too (to prevent chunked
  transfer encoding)

*2009-12-03*
- Updating printIDG and testigddescparse.c for debug.
- Modifications to compile under AmigaOS
- Adding a testminiwget program
- Changed miniwget to advertise itself as HTTP/1.0 to prevent chunked
  transfer encoding

*2009-11-26*
- Fixing updateminiupnpcstrings.sh to take into account
  which command that does not return an error code.

## 1.4 - 2009-10-30

*2009-10-16*
- Using Py_BEGIN_ALLOW_THREADS and Py_END_ALLOW_THREADS in python module.

*2009-10-10*
- Some fixes for compilation under Solaris
- Compilation fixes: http://miniupnp.tuxfamily.org/forum/viewtopic.php?p=1464

*2009-09-21*
- Fixing the code to ignore EINTR during connect() calls.

*2009-08-07*
- Set socket timeout for connect()
- Some cleanup in miniwget.c

*2009-08-04*
- Remove multiple redirections with -d in upnpc.c
- Print textual error code in upnpc.c
- Ignore EINTR during the connect() and poll() calls.

*2009-07-29*
- Fix in updateminiupnpcstrings.sh if OS name contains "/"
- Sending a correct value for MX: field in SSDP request

*2009-07-20*
- Change the Makefile to compile under Mac OS X
- Fixed a stackoverflow in getDevicesFromMiniSSDPD()

*2009-07-09*
- Compile under Haiku
- Generate miniupnpcstrings.h.in from miniupnpcstrings.h

*2009-06-04*
- Patching to compile under CygWin and cross compile for minGW

## 1.3 - 2009-04-17

*2009-04-17*
- Updating python module
- Use strtoull() when using C99

*2009-02-28*
- Fixed miniwget.c for compiling under sun

*2008-12-18*
- Cleanup in Makefile (thanks to Paul de Weerd)
- minissdpc.c: win32 compatibility
- miniupnpc.c: changed xmlns prefix from 'm' to 'u'
- Removed NDEBUG (using DEBUG)

*2008-10-14*
- Added the ExternalHost argument to DeletePortMapping()

*2008-10-11*
- Added the ExternalHost argument to AddPortMapping()
- Put a correct User-Agent: header in HTTP requests.

## 1.2 - 2008-10-07

*2008-10-07*
- Update docs

*2008-09-25*
- Integrated sameport patch from Dario Meloni: Added a "sameport"
  argument to upnpDiscover().

*2008-07-18*
- Small modif to make Clang happy:)

*2008-07-17*
- #define SOAPPREFIX "s" in miniupnpc.c in order to remove SOAP-ENV...

*2008-07-14*
- Include declspec.h in installation (to /usr/include/miniupnpc)

## 1.1 - 2008-07-04

*2008-07-04*
- Standard options for install/ln instead of gnu-specific stuff.

*2008-07-03*
- Now builds a .dll and .lib with win32. (mingw32)

*2008-04-28*
- Make install now install the binary of the upnpc tool

*2008-04-27*
- Added testupnpigd.py
- Added error strings for miniupnpc "internal" errors
- Improved python module error/exception reporting.

*2008-04-23*
- Completely rewrite igd_desc_parse.c in order to be compatible with
  Linksys WAG200G
- Added testigddescparse
- Updated python module

## 1.0 - 2008-02-21

*2008-02-21*
- Put some #ifdef DEBUG around DisplayNameValueList()

*2008-02-18*
- Improved error reporting in upnpcommands.c
- UPNP_GetStatusInfo() returns LastConnectionError

*2008-02-16*
- Better error handling in minisoap.c
- Improving display of "valid IGD found" in upnpc.c

*2008-02-03*
- Fixing UPNP_GetValidIGD()
- Improved make install:)

*2007-12-22*
- Adding upnperrors.c/h to provide a strupnperror() function
  used to translate UPnP error codes to string.

*2007-12-19*
- Fixing getDevicesFromMiniSSDPD()
- Improved error reporting of UPnP functions

*2007-12-18*
- It is now possible to specify a different location for MiniSSDPd socket.
- Working with MiniSSDPd is now more efficient.
- Python module improved.

*2007-12-16*
- Improving error reporting

*2007-12-13*
- Try to improve compatibility by using HTTP/1.0 instead of 1.1 and
- XML a bit different for SOAP.

*2007-11-25*
- Fixed select() call for linux

*2007-11-15*
- Added -fPIC to CFLAG for better shared library code.

*2007-11-02*
- Fixed a potential socket leak in miniwget2()

*2007-10-16*
- Added a parameter to upnpDiscover() in order to allow the use of another
  interface than the default multicast interface.

*2007-10-12*
- Fixed the creation of symbolic link in Makefile

*2007-10-08*
- Added man page

*2007-10-02*
- Fixed memory bug in GetUPNPUrls()

*2007-10-01*
- Fixes in the Makefile
- Added UPNP_GetIGDFromUrl() and adapted the sample program accordingly.
- Added SONAME in the shared library to please debian:)
- Fixed MS Windows compilation (minissdpd is not available under MS Windows).

*2007-09-25*
- Small change to Makefile to be able to install in a different location
  (default is /usr)

*2007-09-24*
- Now compiling both shared and static library

*2007-09-19*
- Cosmetic changes on upnpc.c

*2007-09-02*
- Adapting to new miniSSDPd (release version?)

*2007-08-31*
- Usage of miniSSDPd to skip discovery process.

*2007-08-27*
- Fixed python module to allow compilation with Python older than Python 2.4

*2007-06-12*
- Added a python module.

*2007-05-19*
- Fixed compilation under MinGW

*2007-05-15*
- Fixed a memory leak in AddPortMapping()
- Added testupnpreplyparse executable to check the parsing of
  upnp soap messages
- minixml now ignore namespace prefixes.

*2007-04-26*
- upnpc now displays external ip address with -s or -l

*2007-04-11*
- Changed MINIUPNPC_URL_MAXSIZE to 128 to accommodate the "BT Voyager 210"

*2007-03-19*
- Cleanup in miniwget.c

*2007-03-01*
- Small typo fix...

*2007-01-30*
- Now parsing the HTTP header from SOAP responses in order to
  get content-length value.

*2007-01-29*
- Fixed the Soap Query to speedup the HTTP request.
- Added some Win32 DLL stuff...

*2007-01-27*
- Fixed some WIN32 compatibility issues

*2006-12-14*
- Added UPNPIGD_IsConnected() function in miniupnp.c/.h
- Added UPNP_GetValidIGD() in miniupnp.c/.h
- Cleaned upnpc.c main(). now using UPNP_GetValidIGD()

*2006-12-07*
- Version 1.0-RC1 released

*2006-12-03*
- Minor changes to compile under SunOS/Solaris

*2006-11-30*
- Made a minixml parser validator program
- Updated minixml to handle attributes correctly

*2006-11-22*
- Added a -r option to the upnpc sample thanks to Alexander Hubmann.

*2006-11-19*
- Cleanup code to make it more ANSI C compliant

*2006-11-10*
- Detect and display local lan address.

*2006-11-04*
- Packets and Bytes Sent/Received are now unsigned int.

*2006-11-01*
- Bug fix thanks to Giuseppe D'Angelo

*2006-10-31*
- C++ compatibility for .h files.
- Added a way to get ip Address on the LAN used to reach the IGD.

*2006-10-25*
- Added M-SEARCH to the services in the discovery process.

*2006-10-22*
- Updated the Makefile to use makedepend, added a "make install"
- Update Makefile

*2006-10-20*
- Fixing the description url parsing thanks to patch sent by
  Wayne Dawe.
- Fixed/translated some comments.
- Implemented a better discover process, first looking
  for IGD then for root devices (as some devices only reply to
  M-SEARCH for root devices).

*2006-09-02*
- Added freeUPNPDevlist() function.

*2006-08-04*
- More command line arguments checking

*2006-08-01*
- Added the .bat file to compile under Win32 with minGW32

*2006-07-31*
- Fixed the rootdesc parser (igd_desc_parse.c)

*2006-07-20*
- parseMSEARCHReply() is now returning the ST: line as well
- Starting changes to detect several UPnP devices on the network

*2006-07-19*
- Using GetCommonLinkProperties to get down/upload bitrate

[unreleased]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_6...HEAD
[2.2.6]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_5...miniupnpc_2_2_6
[2.2.5]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_4...miniupnpc_2_2_5
[2.2.4]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_3...miniupnpc_2_2_4
[2.2.3]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_2...miniupnpc_2_2_3
[2.2.2]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_1...miniupnpc_2_2_2
[2.2.1]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_2_0...miniupnpc_2_2_1
[2.2.0]: https://github.com/miniupnp/miniupnp/compare/miniupnpc_2_1...miniupnpc_2_2_0
