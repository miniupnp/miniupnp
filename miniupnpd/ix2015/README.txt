FIXED
	protocl -> protocol typo!


miniupnpd version of UPNP PROXY.

This subsystem under ix2015 tries to

 - control external standalone router device to set or unset port
   forwarding or NAPT on the router by logging into the router device
   using telnet (or you can probably use whatever is available: read
   upnp-auxiliary.pl perl script. It uses telnet for now. It can use a
   serial connection if necessary and possibly ssh. It all depends on
   the router capability, the wiring, and Perl module availability.)

 - Main upnp interaction is handled by miniupnpd. Instead of
   controlling the low-level functions in the case of
   netfilter/ipfw/ip, the function in this subsystem calls the
   external perl script with suitable argument to set up port
   forwarding, etc.

 - Note that this means the gateway of the standalone router that is
   connected to external WAN, and the IP address which is listened by
   miniupnpd are different.

CAVEAT: 

Microsoft UPnP software will not recognize upnp server (such as miniupnpd
or upnp proxy based on libupnp) unless the server is at the default
gateway address!
But skype, Opera's file sharing, and other UPnP clients do work with
this modified daemon although the UPnP server is at a different IP
address from that of default gateway.

Recommendation:
	Run this upnp proxy using "-d" as an ordinary program instead
	of running it as daemon, and monitor the logging output on the
	terminal window where the program is invoked.
	(Under solaris, you have to tweak /etc/syslog.conf and kill
	-HUP syslogd-pid to make sure daemon.debug is captured
	in a file and look at that file. Under Linux, the syslog()
	message is printed to stderr as well as sent to syslogd, and
	so you can read the log on the terminal console if you run
	miniupnpd with "-d".)
	

Restrictions:
	- Only the features available in the configuration
	defined in config.h-linux-ix2015, config.h-solaris-ix2015 are minimally
	tested.
	The header file should copied to config.h before compilation.

	- Proper compiling and linking are tested using
	Makefile.linux-ix2015 under linux (Debian GNU/Linux linux
	kernel 3.x) and Makefile.solaris-ix2015 under solaris 10.

	- Only IPv4 operation is tested.
	(This is because I don't have external IPv6 connection and so
	didn't feel the necessity for IPv6 operation.)

How to Compile and Run

(Under linux) 

    Preparation   
    It is necessary to install libbsd-dev package to use strlcpy()
    function, and you need to specify -lbsd on the link line.  
    If you encounter an error during linking regarding missing
    strlcpy() function, then install libbsd-dev package.  

    To install on Debian GNU/Linux (and presumably on Ubuntu):
    aptitude update
    aptitude install libbsd-dev

 -  Compilation Under Linux

    The linker option -lbsd is already specified in
    Makefile.linux-ix2015

    make -f Makefile.linux-ix2015

    It will begin to run genconfig.sh, interrupt it with control-C.
    The framework for upnp proxy is very different from the
    original miniupnd, and genconfig.sh
    may get hung if you don't have netfilter/ip/ipfw, etc.

    Just copy the config.h-linux-ix2015 to config.h

    cp config.h-linux-ix2015 config.h 
    make -f Makefile.linux-ix2015

    This should create miniupnpd.

    Compilation under solaris 10

(Under Solaris 10 or 11a) 

 -   Compile under solaris 10

    You have to use gmake (from opencsw repository).
    Of course, you have to install gcc in advance. 

    cp config.h-solaris-ix2015 config.h

    CC=gcc gmake -f Makefile.solaris-ix2015

    I don't know why but I have to put CC=gcc in front of gmake.

    ( CC="purify gcc" gmake -f Makefile.solaris-ix2015 for using
    purify and gcc. This is how actually tested miniupnpd under
    solaris. )

    The above make command may begin to run genconfig.sh, interrupt it
    with control-C.
    Just make sure that you copied config.h-solaris-ix2015 to config.h.

    The make command should create miniupnpd.

    (I think the miniupnpd will compile and run under solaris11, too.
     I didn't test it since I did not have purify under it yet.)

(Running miniupnpd with ix2015 upnp proxy function.)

	Firstly, copy upnp-auxiliary.pl-real under ix2015 directory
	to
	ix2015/upnp-auxiliary.pl

	cp ix2015/upnp-auxiliary.pl-real ix2015/upnp-auxiliary.pl

	This is the script to log into the router and modify firewall
	rules.  (It is currently written for NEC ix2015 router.  This
	has to be modified for a particular brand of the
	router/firewall you use. Someone has already ported this to
	his setup of NetScreen firewall. Cisco router with IOS CLI
	would be an easy target since the syntax and functionality
	seems to be very close to those of ix2015 CLI.)
	 
	(upnp-auxiliary.pl-dummy is a script for debugging under an
	environment where the router is NOT present. It simply returns
	the initial rules present in the faked response.)

	As the above recommendation suggests, run this version of
	miniupnpd as an ordinary program to control an external router.
	You don't need root privilege (except for writing to a default
	PID lock file. You can use "-p" to specify a writable file to
	avoid the problem.) 

	So simply run ./miniupnpd under the directory
	where it is compiled and linked.  (The main miniupnpd directory.)
	It uses external program wait-usec 
	and ix2015/upnp-auxiliary.pl (perl script).


	Argument:

	-i interface

	This interface has no meaning in ix2015 UPNP Proxy setup.
	You can specify anything.

		Example:
			-i dummy


	-v verbosity
	To increase verbosity from ix2015 functions, you can specify
	-v. You can specify them as many times as you want. Once
	instance of "-v" will increment verbosity level. Usually two
	or three are enough.

        -a IP/MASK
        Don't forget to specify mask on IP. You can specify as many
        IP addresses necessary including 127.0.0.1.

	If the mask is missing, you will get errors like:

	miniupnpd[15615]: Can't find in which sub network the client is

	Example:
	$ ./miniupnpd -d -v -v -v -i dummy -a 10.254.225.253/255.128.0.0 -P /tmp/pid-upnp


	Or

	$ ./miniupnpd -v -v -v -d -f /tmp/t.conf -i ixxx -a 192.168.0.5/255.255.255.0 -P /tmp/pid-upnp

	Error example: 
	gupnp-universal-cp does not recognize this daemon reliably
	on the same linux machine. I have to add  127.0.0.1 as one of the
	listening address to make it work reliably:

	"-a 127.0.0.1/255.255.255.0"

        ./miniupnpd -d -v -v -v -i dummy -a 127.0.0.1/255.255.255.0 -a 10.254.225.253/255.128.0.0 -P /tmp/pid-upnp

	E.g.:
	./miniupnpd -i dummy -d -v -v -v -a 127.0.0.1/255.255.255.0 \
	-a aaa.bbb.cccc.ddd/mmm.aaa.sss.kkk -f  yourconf file -p /tmp/upnp-pid

	For running the external perl script, you may need to install
	extra packages.  If you encounter an error while the external
	script is invoked, you need to install missing packages.
	Read README*.txt files from
	upnpproxy.sourceforge.net if you find you need to install some
	missing PERL packages.

Files used.

    Below, the file path "./" indicates the main miniupnpd directory
    (i.e., the one above the directory where this README.txt is
    located.), and where miniupnpd should be run as an ordinary user
    program.  The file path "ix2015/" indicates this directory where
    README.txt is located.

External Program required
	 ix2015/upnp-auxiliary.pl	... PERL script to set up router.
	 ./wait-usec		... external program to insert delay.

External/Temporary Files generated:

	 In order to keep track of the latest router operation, the
	 program and external script will write the following files to
	 the current directory.

	 ./router-dump.txt     	 ... router CLI interaction output.
	 ./router-dump.txt.old
	 ./igd-dump.txt		... summarized router status.

	 /tmp/t.action		... Information on action on the router.
	 /tmp/t.action.old

Operational Issues:

Maybe the program is too verbose, but it is necessary to keep track of
what goes wrong.

  - We use CLI interface designed for human operation.
  Sometimes too fast interaction via computer program may drop
  some characters or even lines inadvertently. This happened.

  So to analyze this type of error, router response may need to be
  kept track.  Without verbose logging, it is hard to realize such
  bugs caused by external factors.

 - Also, there is only a very loose coordination between the external
 router and the control program. Anyone can influence the router setup
 out of band from the view point of this control program. Again, we
 need to keep track of errors caused by such unexpected changes
 outside the control of this program.

****************************************

TODO/FIXME: PUT vs GET

	    I noticed that Opera (and its file sharing) tries to call
	    GET /ctl/IPconn once and fails.
	    Maybe I should investigate what is going on.

miniupnpd[29568]: ****************************************
miniupnpd[29568]: Registering at i=10
miniupnpd[29568]: creating pass rule to 192.168.0.112:8840 protocol 6 for: Opera Unite
miniupnpd[29568]: HTTP connection from 192.168.0.112:49967
miniupnpd[29568]: HTTP REQUEST : GET /ctl/IPConn (HTTP/1.1)
miniupnpd[29568]: /ctl/IPConn not found, responding ERROR 404
miniupnpd[29568]: HTTP connection from 192.168.0.112:50359
miniupnpd[29568]: HTTP REQUEST : POST /ctl/IPConn (HTTP/1.1)
miniupnpd[29568]: SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry

===============
Changes

- ./getifstat.c
	now a dummy function simply to return IP address obtain from
	the external script.

- is_restricted(int portnum) now returns 0 for all port numbers (no
restriction).
The checking for port number is done in upper level miniupnpd code.

- Makefile.linux-ix2015

  set LNXOBJS to null string in ./Makefile.linux-ix2015

  PROXOBJS is set to ix2015/ipfwrdr.o

  config.h 

TODO/FIXME

 - Right now, the ix2015 upnp proxy function has been ported from UPNP
   Proxy (upnpproxy.sourceforge.net) with minimal changes.
   So there may be a duplication for insertion check. miniupnpd checks if
   a rule already exists when it receives a set up for forwarding
   rule. So it searches for a matching rule by calling low-level
   routines (get_redirect_rule)  and it seems to finally to set up a
   forwarding rule  only when it does not
   find the matching rule. (Or maybe I am wrong).
   But the low-level upnp proxy function also performs its own sanity
   check to find a matching rule before setting up a forwarding rule.
   So you may see similar looking lookup activity log just before
   a forwarding rule is finally set up on the router.
  (I could be wrong on the above scenario.)

 - is_restricted() has to return 0 in all cases.

   The ported code assumes that the upper level code does the same
   checking using is_restricted(), but not in this case of miniupnpd()
   that has a flexible user-defined checking (in config file, for
   example).  So if a port is restricted by is_restricted(), but not
   by the upper-level miniupnpd code based on the user setup, across
   the stop/re-start of miniupnpd, the dump file may contain the
   restricted port (is_restricted()== non-zero) because miniupnpd
   allows it. But upon restart, when the router status dump file is
   read, the low-level recover routine skips such
   (is_restricted()==non-zero) port from its management because it
   thinks it is protected (is_restricted()==non-zero) and should not
   be handled by the code at all.  Thus now is_protected() returns
   0 for all ports.

 - Use proper level/facility for syslog() additions
   Mostly done hopefully.

 - remove garbage characters? in WEXITSTATUS message line.
   strerrmsg_r() seems to be buggy under linux.
   (No garbage characters under solaris.)
   They seem to be gone?
	
Why not windows live messenger?

    Windows live messnger only recognizes the UPnP server if it
    is at the same IP address as default gateway.
    So maybe:
    We need to assign default gateway to the linux/solaris interface
    and then probably route the packet from there to the real
    router interface to reach the external WAN  (by IGMP redirect,
    or maybe ip/ipfw/fw rules? That sounds too onus.)

    Well, I used a linux version of miniupnpd and did just that.
    However, windows live messenger tried to
    map external port 34770 to an internal port 4760 and
    the eport != iport combination is not supported as of now by
    the UPnP proxy function, and so the mapping failed.

    Real log.
    miniupnpd[25842]: AddPortMapping: ext port 34770 to 192.168.0.17:4670 protocol TCP for: msnmsgr (192.168.0.17:4670) 34770 TCP leaseduration=0 rhost={NULL}
    miniupnpd[25842]: upnp_redirect: eport=34770, iport=4670, protocol=<<TCP>>
    miniupnpd[25842]: iaddr=192.168.0.17, desc=msnmsgr (192.168.0.17:4670) 34770 TCP, leaseduration=0
    miniupnpd[25842]: no permission rule matched : accept by default (n_perms=0)
    miniupnpd[25842]: get_redirect_rule:
    miniupnpd[25842]:     eport = 34770, proto = 6, ifname=<<ixxx>>
    upnp_proxy_validate_protocol: TCP
    upnp_proxy_validate_ifname: <<ixxx>>
    info: i=0, used=1, externalPort=52321, protocol=TCP
    info: i=1, used=1, externalPort=52321, protocol=UDP
    info: i=2, used=1, externalPort=29789, protocol=TCP
    info: i=3, used=1, externalPort=29789, protocol=UDP
    info: i=4, used=1, externalPort=12331, protocol=UDP
    info: i=5, used=1, externalPort=12345, protocol=TCP
    info: i=6, used=1, externalPort=34555, protocol=UDP
    info: i=7, used=1, externalPort=34556, protocol=TCP
    info: i=8, used=0, externalPort=0, protocol=
    info: i=9, used=0, externalPort=0, protocol=
    info: i=10, used=0, externalPort=0, protocol=
    info: i=11, used=0, externalPort=0, protocol=
    info: i=12, used=0, externalPort=0, protocol=
    info: i=13, used=0, externalPort=0, protocol=
    info: i=14, used=0, externalPort=0, protocol=
    info: i=15, used=0, externalPort=0, protocol=
    info: i=16, used=0, externalPort=0, protocol=
    info: i=17, used=0, externalPort=0, protocol=
    info: i=18, used=0, externalPort=0, protocol=
    info: i=19, used=0, externalPort=0, protocol=
    miniupnpd[25842]:     Not Found
    miniupnpd[25842]: redirecting port 34770 to 192.168.0.17:4670 protocol TCP for: msnmsgr (192.168.0.17:4670) 34770 TCP
    miniupnpd[25842]: upnp_redirect_internal: reedirecting port 34770 to 192.168.0.17:4670 protocol 6 for: msnmsgr (192.168.0.17:4670) 34770 TCP
    upnp_proxy_validate_protocol: TCP
    upnp_proxy_validate_ifname: <<ixxx>>
    miniupnpd[25842]: add_redirect_rule2:
    miniupnpd[25842]:    protocol: TCP, ifname: ixxx
    miniupnpd[25842]:    iaddr: <<192.168.0.17>>
    miniupnpd[25842]:    eport: 34770, iport: 4670
    miniupnpd[25842]:    desc:  <<msnmsgr (192.168.0.17:4670) 34770 TCP>>
    miniupnpd[25842]:    timestamp:        0
    miniupnpd[25842]: error: Does not support eeport(34770) != iport(4670)
    *** Error: Does not support eport(34770) != iport(4670)
    miniupnpd[25842]: Returning UPnPError 501: ActionFailed

FIXED
	protocl -> protocol typo!


miniupnpd version of UPNP PROXY.

This subsystem under ix2015 tries to

 - control external standalone router device to set or unset port
   forwarding or NAPT on the router by logging into the router device
   using telnet (or you can probably use whatever is available: read
   upnp-auxiliary.pl perl script. It uses telnet for now. It can use a
   serial connection if necessary and possibly ssh. It all depends on
   the router capability, the wiring, and Perl module availability.)

 - Main upnp interaction is handled by miniupnpd. Instead of
   controlling the low-level functions in the case of
   netfilter/ipfw/ip, the function in this subsystem calls the
   external perl script with suitable argument to set up port
   forwarding, etc.

 - Note that this means the gateway of the standalone router that is
   connected to external WAN, and the IP address which is listened by
   miniupnpd are different.

CAVEAT: 

Microsoft UPnP software will not recognize upnp server (such as miniupnpd
or upnp proxy based on libupnp) unless the server is at the default
gateway address!
But skype, Opera's file sharing, and other UPnP clients do work with
this modified daemon although the UPnP server is at a different IP
address from that of default gateway.

Recommendation:
	Run this upnp proxy using "-d" as an ordinary program instead
	of running it as daemon, and monitor the logging output on the
	terminal window where the program is invoked.
	(Under solaris, you have to tweak /etc/syslog.conf and kill
	-HUP syslogd-pid to make sure daemon.debug is captured
	in a file and look at that file. Under Linux, the syslog()
	message is printed to stderr as well as sent to syslogd, and
	so you can read the log on the terminal console if you run
	miniupnpd with "-d".)
	

Restrictions:
	- Only the features available in the configuration
	defined in config.h-linux-ix2015, config.h-solaris-ix2015 are minimally
	tested.
	The header file should copied to config.h before compilation.

	- Proper compiling and linking are tested using
	Makefile.linux-ix2015 under linux (Debian GNU/Linux linux
	kernel 3.x) and Makefile.solaris-ix2015 under solaris 10.

	- Only IPv4 operation is tested.
	(This is because I don't have external IPv6 connection and so
	didn't feel the necessity for IPv6 operation.)

How to Compile and Run

(Under linux) 

    Preparation   
    It is necessary to install libbsd-dev package to use strlcpy()
    function, and you need to specify -lbsd on the link line.  
    If you encounter an error during linking regarding missing
    strlcpy() function, then install libbsd-dev package.  

    To install on Debian GNU/Linux (and presumably on Ubuntu):
    aptitude update
    aptitude install libbsd-dev

 -  Compilation Under Linux

    The linker option -lbsd is already specified in
    Makefile.linux-ix2015

    make -f Makefile.linux-ix2015

    It will begin to run genconfig.sh, interrupt it with control-C.
    The framework for upnp proxy is very different from the
    original miniupnd, and genconfig.sh
    may get hung if you don't have netfilter/ip/ipfw, etc.

    Just copy the config.h-linux-ix2015 to config.h

    cp config.h-linux-ix2015 config.h 
    make -f Makefile.linux-ix2015

    This should create miniupnpd.

    Compilation under solaris 10

(Under Solaris 10 or 11a) 

 -   Compile under solaris 10

    You have to use gmake (from opencsw repository).
    Of course, you have to install gcc in advance. 

    cp config.h-solaris-ix2015 config.h

    CC=gcc gmake -f Makefile.solaris-ix2015

    I don't know why but I have to put CC=gcc in front of gmake.

    ( CC="purify gcc" gmake -f Makefile.solaris-ix2015 for using
    purify and gcc. This is how actually tested miniupnpd under
    solaris. )

    The above make command may begin to run genconfig.sh, interrupt it
    with control-C.
    Just make sure that you copied config.h-solaris-ix2015 to config.h.

    The make command should create miniupnpd.

    (I think the miniupnpd will compile and run under solaris11, too.
     I didn't test it since I did not have purify under it yet.)

(Running miniupnpd with ix2015 upnp proxy function.)

	Firstly, copy upnp-auxiliary.pl-real under ix2015 directory
	to
	ix2015/upnp-auxiliary.pl

	cp ix2015/upnp-auxiliary.pl-real ix2015/upnp-auxiliary.pl

	This is the script to log into the router and modify firewall
	rules.  (It is currently written for NEC ix2015 router.  This
	has to be modified for a particular brand of the
	router/firewall you use. Someone has already ported this to
	his setup of NetScreen firewall. Cisco router with IOS CLI
	would be an easy target since the syntax and functionality
	seems to be very close to those of ix2015 CLI.)
	 
	(upnp-auxiliary.pl-dummy is a script for debugging under an
	environment where the router is NOT present. It simply returns
	the initial rules present in the faked response.)

	As the above recommendation suggests, run this version of
	miniupnpd as an ordinary program to control an external router.
	You don't need root privilege (except for writing to a default
	PID lock file. You can use "-p" to specify a writable file to
	avoid the problem.) 

	So simply run ./miniupnpd under the directory
	where it is compiled and linked.  (The main miniupnpd directory.)
	It uses external program wait-usec 
	and ix2015/upnp-auxiliary.pl (perl script).


	Argument:

	-i interface

	This interface has no meaning in ix2015 UPNP Proxy setup.
	You can specify anything.

		Example:
			-i dummy


	-v verbosity
	To increase verbosity from ix2015 functions, you can specify
	-v. You can specify them as many times as you want. Once
	instance of "-v" will increment verbosity level. Usually two
	or three are enough.

        -a IP/MASK
        Don't forget to specify mask on IP. You can specify as many
        IP addresses necessary including 127.0.0.1.

	If the mask is missing, you will get errors like:

	miniupnpd[15615]: Can't find in which sub network the client is

	Example:
	$ ./miniupnpd -d -v -v -v -i dummy -a 10.254.225.253/255.128.0.0 -P /tmp/pid-upnp


	Or

	$ ./miniupnpd -v -v -v -d -f /tmp/t.conf -i ixxx -a 192.168.0.5/255.255.255.0 -P /tmp/pid-upnp

	Error example: 
	gupnp-universal-cp does not recognize this daemon reliably
	on the same linux machine. I have to add  127.0.0.1 as one of the
	listening address to make it work reliably:

	"-a 127.0.0.1/255.255.255.0"

        ./miniupnpd -d -v -v -v -i dummy -a 127.0.0.1/255.255.255.0 -a 10.254.225.253/255.128.0.0 -P /tmp/pid-upnp

	E.g.:
	./miniupnpd -i dummy -d -v -v -v -a 127.0.0.1/255.255.255.0 \
	-a aaa.bbb.cccc.ddd/mmm.aaa.sss.kkk -f  yourconf file -p /tmp/upnp-pid

	For running the external perl script, you may need to install
	extra packages.  If you encounter an error while the external
	script is invoked, you need to install missing packages.
	Read README*.txt files from
	upnpproxy.sourceforge.net if you find you need to install some
	missing PERL packages.

Files used.

    Below, the file path "./" indicates the main miniupnpd directory
    (i.e., the one above the directory where this README.txt is
    located.), and where miniupnpd should be run as an ordinary user
    program.  The file path "ix2015/" indicates this directory where
    README.txt is located.

External Program required
	 ix2015/upnp-auxiliary.pl	... PERL script to set up router.
	 ./wait-usec		... external program to insert delay.

External/Temporary Files generated:

	 In order to keep track of the latest router operation, the
	 program and external script will write the following files to
	 the current directory.

	 ./router-dump.txt     	 ... router CLI interaction output.
	 ./router-dump.txt.old
	 ./igd-dump.txt		... summarized router status.

	 /tmp/t.action		... Information on action on the router.
	 /tmp/t.action.old

Operational Issues:

Maybe the program is too verbose, but it is necessary to keep track of
what goes wrong.

  - We use CLI interface designed for human operation.
  Sometimes too fast interaction via computer program may drop
  some characters or even lines inadvertently. This happened.

  So to analyze this type of error, router response may need to be
  kept track.  Without verbose logging, it is hard to realize such
  bugs caused by external factors.

 - Also, there is only a very loose coordination between the external
 router and the control program. Anyone can influence the router setup
 out of band from the view point of this control program. Again, we
 need to keep track of errors caused by such unexpected changes
 outside the control of this program.

****************************************

TODO/FIXME: PUT vs GET

	    I noticed that Opera (and its file sharing) tries to call
	    GET /ctl/IPconn once and fails.
	    Maybe I should investigate what is going on.

miniupnpd[29568]: ****************************************
miniupnpd[29568]: Registering at i=10
miniupnpd[29568]: creating pass rule to 192.168.0.112:8840 protocol 6 for: Opera Unite
miniupnpd[29568]: HTTP connection from 192.168.0.112:49967
miniupnpd[29568]: HTTP REQUEST : GET /ctl/IPConn (HTTP/1.1)
miniupnpd[29568]: /ctl/IPConn not found, responding ERROR 404
miniupnpd[29568]: HTTP connection from 192.168.0.112:50359
miniupnpd[29568]: HTTP REQUEST : POST /ctl/IPConn (HTTP/1.1)
miniupnpd[29568]: SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry

===============
Changes

- ./getifstat.c
	now a dummy function simply to return IP address obtain from
	the external script.

- is_restricted(int portnum) now returns 0 for all port numbers (no
restriction).
The checking for port number is done in upper level miniupnpd code.

- Makefile.linux-ix2015

  set LNXOBJS to null string in ./Makefile.linux-ix2015

  PROXOBJS is set to ix2015/ipfwrdr.o

  config.h 

TODO/FIXME

 - Right now, the ix2015 upnp proxy function has been ported from UPNP
   Proxy (upnpproxy.sourceforge.net) with minimal changes.
   So there may be a duplication for insertion check. miniupnpd checks if
   a rule already exists when it receives a set up for forwarding
   rule. So it searches for a matching rule by calling low-level
   routines (get_redirect_rule)  and it seems to finally to set up a
   forwarding rule  only when it does not
   find the matching rule. (Or maybe I am wrong).
   But the low-level upnp proxy function also performs its own sanity
   check to find a matching rule before setting up a forwarding rule.
   So you may see similar looking lookup activity log just before
   a forwarding rule is finally set up on the router.
  (I could be wrong on the above scenario.)

 - is_restricted() has to return 0 in all cases.

   The ported code assumes that the upper level code does the same
   checking using is_restricted(), but not in this case of miniupnpd()
   that has a flexible user-defined checking (in config file, for
   example).  So if a port is restricted by is_restricted(), but not
   by the upper-level miniupnpd code based on the user setup, across
   the stop/re-start of miniupnpd, the dump file may contain the
   restricted port (is_restricted()== non-zero) because miniupnpd
   allows it. But upon restart, when the router status dump file is
   read, the low-level recover routine skips such
   (is_restricted()==non-zero) port from its management because it
   thinks it is protected (is_restricted()==non-zero) and should not
   be handled by the code at all.  Thus now is_protected() returns
   0 for all ports.

 - Use proper level/facility for syslog() additions
   Mostly done hopefully.

 - remove garbage characters? in WEXITSTATUS message line.
   strerrmsg_r() seems to be buggy under linux.
   (No garbage characters under solaris.)
   They seem to be gone?
	
Why not windows live messenger?

    Windows live messnger only recognizes the UPnP server if it
    is at the same IP address as default gateway.
    So maybe:
    We need to assign default gateway to the linux/solaris interface
    and then probably route the packet from there to the real
    router interface to reach the external WAN  (by IGMP redirect,
    or maybe ip/ipfw/fw rules? That sounds too onus.)

    Well, I used a linux version of miniupnpd and did just that.

    1. the default gateway address known to live messenger is changed to
    the port address to which  upnp-proxy miniupnpd listens.

    2. Assume linux for miniupnpd, and then
    sysctl -w net.ipv4.ip_forward=1

    3. Set the default gateway of linux to that of ix2015 router.


    However, windows live messenger tried to
    map external port 34770 to an internal port 4760 and
    the eport != iport combination is not supported as of now by
    the UPnP proxy function, and so the mapping failed.

    Real log.
    miniupnpd[25842]: AddPortMapping: ext port 34770 to 192.168.0.17:4670 protocol TCP for: msnmsgr (192.168.0.17:4670) 34770 TCP leaseduration=0 rhost={NULL}
    miniupnpd[25842]: upnp_redirect: eport=34770, iport=4670, protocol=<<TCP>>
    miniupnpd[25842]: iaddr=192.168.0.17, desc=msnmsgr (192.168.0.17:4670) 34770 TCP, leaseduration=0
    miniupnpd[25842]: no permission rule matched : accept by default (n_perms=0)
    miniupnpd[25842]: get_redirect_rule:
    miniupnpd[25842]:     eport = 34770, proto = 6, ifname=<<ixxx>>
    upnp_proxy_validate_protocol: TCP
    upnp_proxy_validate_ifname: <<ixxx>>
    info: i=0, used=1, externalPort=52321, protocol=TCP
    info: i=1, used=1, externalPort=52321, protocol=UDP
    info: i=2, used=1, externalPort=29789, protocol=TCP
    info: i=3, used=1, externalPort=29789, protocol=UDP
    info: i=4, used=1, externalPort=12331, protocol=UDP
    info: i=5, used=1, externalPort=12345, protocol=TCP
    info: i=6, used=1, externalPort=34555, protocol=UDP
    info: i=7, used=1, externalPort=34556, protocol=TCP
    info: i=8, used=0, externalPort=0, protocol=
    info: i=9, used=0, externalPort=0, protocol=
    info: i=10, used=0, externalPort=0, protocol=
    info: i=11, used=0, externalPort=0, protocol=
    info: i=12, used=0, externalPort=0, protocol=
    info: i=13, used=0, externalPort=0, protocol=
    info: i=14, used=0, externalPort=0, protocol=
    info: i=15, used=0, externalPort=0, protocol=
    info: i=16, used=0, externalPort=0, protocol=
    info: i=17, used=0, externalPort=0, protocol=
    info: i=18, used=0, externalPort=0, protocol=
    info: i=19, used=0, externalPort=0, protocol=
    miniupnpd[25842]:     Not Found
    miniupnpd[25842]: redirecting port 34770 to 192.168.0.17:4670 protocol TCP for: msnmsgr (192.168.0.17:4670) 34770 TCP
    miniupnpd[25842]: upnp_redirect_internal: reedirecting port 34770 to 192.168.0.17:4670 protocol 6 for: msnmsgr (192.168.0.17:4670) 34770 TCP
    upnp_proxy_validate_protocol: TCP
    upnp_proxy_validate_ifname: <<ixxx>>
    miniupnpd[25842]: add_redirect_rule2:
    miniupnpd[25842]:    protocol: TCP, ifname: ixxx
    miniupnpd[25842]:    iaddr: <<192.168.0.17>>
    miniupnpd[25842]:    eport: 34770, iport: 4670
    miniupnpd[25842]:    desc:  <<msnmsgr (192.168.0.17:4670) 34770 TCP>>
    miniupnpd[25842]:    timestamp:        0
    miniupnpd[25842]: error: Does not support eeport(34770) != iport(4670)
    *** Error: Does not support eport(34770) != iport(4670)
    miniupnpd[25842]: Returning UPnPError 501: ActionFailed


---
Solaris port check

Under solaris, printing NULL pointer by format conversion character
"%s" causes a segmentation fault. That is life.  So I had to take care
of a few places where such printing of NULL pointer may happen under
rare circumstances. I also uncovered a few latent bugs in doing so.
Under linux, usually printing NULL using "%s" conversion prints
"(nil)" (or {NULL}, case ignored).


[end of file]
