Analysis of API


What we probably needs.

add_redirect_rule2
delete_redirect_rule

get_portmappings_in_range ???

get_redirect_rule

	/* upnp_redirect() 
	 * invokes system-specific action of the redirection.
	 * protocol: "TCP" or "UDP"
	 * returns: 0 on success
	 *          -1 failed to redirect
	 *          -2 already redirected
	 *          -3 permission check failed
	 */
	int
	AUX_upnp_redirect (int eport,
			   const char *iaddr,
			   int iport,
			   const char *protocol, 
			   const char *desc, 
			   int leaseduration)


========================================
What we have:

{   0} AUX_upnp_redirect() <int AUX_upnp_redirect (int eport, const char *iaddr, int iport, const char *protocol, const char *desc, int leaseduration) at template-action-function.c:1086>:

{   1}     ix2015_add_mapping() <int ix2015_add_mapping (int eport, char protocol[], char internalip[]) at template-action-function.c:524>:

{   0} IGD_NAT_rule_dump() <void IGD_NAT_rule_dump (void) at template-action-function.c:629>:

{   0} IGD_NAT_rule_load() <int IGD_NAT_rule_load (void) at template-action-function.c:761>:

{   0} delay_system_if_too_rapid() <void delay_system_if_too_rapid (int is_add) at template-action-function.c:245>:

{   0} getNumericIP4Addr_Port() <void getNumericIP4Addr_Port (struct sockaddr_storage ip, char host[], size_t hsize, char port[], size_t psize) at template-action-function.c:187>:
{   0} upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries (void) at template-action-function.c:369>:

{   0} upnp_redirect() <int upnp_redirect (int eport, const char *iaddr, int iport, const char *protocol, const char *desc, int leaseduration) at template-action-function.c:1203>:

static
int
AUX_upnp_delete_redirection (int eport, const char *protocol)
{


========================================


get_redirect_rule_by_index
init_redirect
shutdown_redirect

==================
*   1 add_redirect_rule2: int (const char *ifname, const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp), <ipfwrdr.c 171>
    2     ipfw_validate_protocol: <>
    3     ipfw_validate_ifname: <>
    4     printf: <>
    5     add_desc_time: void (unsigned short eport, int proto, const char *desc, unsigned int timestamp), <ipfwrdr.c 111>
    6         strlen: <>
    7         malloc: <>
    8         memcpy: <>
*   9 delete_redirect_rule: int (const char *ifname, unsigned short eport, int proto), <ipfwrdr.c 273>
   10     ipfw_validate_protocol: <>
   11     ipfw_validate_ifname: <>
   12     ipfw_fetch_ruleset: <>
   13     ipfw_exec: <>
   14     ipfw_free_ruleset: <>
   15     del_desc_time: void (unsigned short eport, int proto), <ipfwrdr.c 133>
   16         free: <>
*  17 get_portmappings_in_range: unsigned short * (unsigned short startport, unsigned short endport, int proto, unsigned int *number), <ipfwrdr.c 406>
   18     ipfw_validate_protocol: <>
   19     ipfw_fetch_ruleset: <>
   20     calloc: <>
   21     syslog: <>
   22     realloc: <>
   23     ipfw_free_ruleset: <>
*  24 get_redirect_rule: int (const char *ifname, unsigned short eport, int proto, char *iaddr, int iaddrlen, unsigned short *iport, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *timestamp, u_int64_t *packets, u_int64_t *bytes), <ipfwrdr.c 204>
   25     ipfw_validate_protocol: <>
   26     ipfw_validate_ifname: <>
   27     ipfw_fetch_ruleset: <>
   28     inet_ntop: <>
   29     syslog: <>
   30     ipfw_free_ruleset: <>
   31     get_desc_time: void (unsigned short eport, int proto, char *desc, int desclen, unsigned int *timestamp), <ipfwrdr.c 153>
   32         strlcpy: <>
*  33 get_redirect_rule_by_index: int (int index, char *ifname, unsigned short *eport, char *iaddr, int iaddrlen, unsigned short *iport, int *proto, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *timestamp, u_int64_t *packets, u_int64_t *bytes), <ipfwrdr.c 330>
   34     ipfw_fetch_ruleset: <>
   35     strlcpy: <>
   36     inet_ntop: <>
   37     syslog: <>
   38     ipfw_free_ruleset: <>
   39     get_desc_time: 31
*  40 init_redirect: int (void), <ipfwrdr.c 76>
   41     ipfw_exec: <>
*  42 shutdown_redirect: void (void), <ipfwrdr.c 87>
   43     ipfw_exec: <>



upnp proxy 

int
upnp_redirect (int eport,
	       const char *iaddr,
	       int iport,
	       const char *protocol, const char *desc, int leaseduration);


/*
 * # of mapping entries.
 * also renumber the visible indices.
 *
 * Not THREAD-SAFE. Callers beware.
 */
int
upnp_get_portmapping_number_of_entries (void)


//
// add NAT mapping rule
//

static int
ix2015_add_mapping (int eport, char protocol[], char internalip[])

//
// remove NAT mapping rule
//
static int
ix2015_remove_mapping (int eport, char protocol[], char internalip[])

//
// Dump internal NAT mapping table.
//
// Saved file format:
// XNport,ipaddress,proto,description...
//
void
IGD_NAT_rule_dump (void)

// Read a line from external NAT mapping file.
// Data Format on each line
// XNportnum,ipaddr,protocol,
// if desc_is_sought is non-zero, description string is also read.
//
int
IGD_NAT_rule_load_NAT_line (char line[],

//
// On startup, load from both the dump files from the real router
// and the dump from the previous run of this program and
// does something clever (like associating the description from
// the former program dump to the current router mapping).
//
// returns a negative value if the router data is not available.
//
int
IGD_NAT_rule_load (void)

//
// CAUTION:
// redirection table handling should be mutex-protected!
//

/* get_redirect_rule() gets internal IP and port from
 * interface, external port and protocl
 */

/* upnp_redirect() 
 * invokes system-specific action of the redirection.
 * protocol: "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */
int
AUX_upnp_redirect (int eport,
		   const char *iaddr,
		   int iport,
		   const char *protocol, 
		   const char *desc, 
		   int leaseduration)


int
upnp_redirect (int eport,
	       const char *iaddr,
	       int iport,
	       const char *protocol, const char *desc, int leaseduration)

	       calls   within lock protection

	       rc = AUX_upnp_redirect (eport, iaddr, iport, protocol, desc, leaseduration);



/* AUX_upnp_delete_redirection()
 * returns: 0 on success
 *          -1 on failure.
 *
 * Non MT-Safe. Protect this with mutex before call.
 */
static
int
AUX_upnp_delete_redirection (int eport, const char *protocol)

/* upnp_delete_redirection()
 * returns: 0 on success
 *          -1 on failure*/
static
int
upnp_delete_redirection (int eport, const char *protocol)

			calls AUX_unp_delete_redirection within lock

/*
 * upnp_get_redirection_infos(eport, protocol).
 * Non-thread safe version. Protect with mutex before calling this function.
 */
static int
AUX_upnp_get_redirection_infos (int eport,
				char protocol[],
				int *iportp,
				char int_ip[],
				int int_ip_len,
				char desc[], int desc_len, int *leasetimep)

static int
upnp_get_redirection_infos 
(
 int eport,			/* IN */
 char protocol[],		/* IN */
 int *iportp,			/* IN */
 char int_ip[],			/* OUT */
 int int_ip_len,
 char desc[],			/* OUT */
 int desc_len, 
 int *leasetimep		/* OUT */
 )
{



/* upnp_redirect()
 * calls OS/fw dependant implementation of the redirection.
 * protocol should be the string "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */

 0 on success
 -1 failure

: already checked before upnp_redirect_internal is called
// -2 already redirected        
//  -3 permission check failed?
		return upnp_redirect_internal(rhost, eport, iaddr, iport, proto,
		                              desc, timestamp);

cflow -l -r upnpredirect.c





{   0} add_filter_rule2():

{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>

/* upnp_redirect()
 * calls OS/fw dependant implementation of the redirection.
 * protocol should be the string "TCP" or "UDP"
 * returns: 0 on success
 *          -1 failed to redirect
 *          -2 already redirected
 *          -3 permission check failed
 */

{   0} add_redirect_rule2():

{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>




TBD
{   0} check_rule_from_file():
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   1}     upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>


{   0} check_upnp_rule_against_permissions():

	if(!check_upnp_rule_against_permissions(upnppermlist, num_upnpperm,
	                                        eport, address, iport)) {
		syslog(LOG_INFO, "redirection permission check failed for "
		                 "%hu->%s:%hu %s", eport, iaddr, iport, protocol);
		return -3;
	}

{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>

{   0} delete_filter_rule():

	#if defined(__linux__)
		r = delete_redirect_and_filter_rules(eport, proto);
	#else
		r = delete_redirect_rule(ext_if_name, eport, proto);
		delete_filter_rule(ext_if_name, eport, proto);
	#endif

{   0} delete_redirect_and_filter_rules():

	#if defined(__linux__)
		r = delete_redirect_and_filter_rules(eport, proto);
	#else
		r = delete_redirect_rule(ext_if_name, eport, proto);
		delete_filter_rule(ext_if_name, eport, proto);
	#endif

{   0} delete_redirect_rule():

		/* clean up the redirect rule */
	#if !defined(__linux__)
			delete_redirect_rule(ext_if_name, eport, proto);
	#endif


{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>


{   0} get_portmappings_in_range():
    /* upnp_get_portmappings_in_range()
     * return a list of all "external" ports for which a port
      * mapping exists */

	return get_portmappings_in_range(startport, endport, proto, number);


{   1}     upnp_get_portmappings_in_range() <unsigned short *upnp_get_portmappings_in_range (unsigned short startport, unsigned short endport, const char *protocol, unsigned int *number) at upnpredirect.c:568>

{   0} get_redirect_rule():

	r = get_redirect_rule(ext_if_name, eport, proto,
	                      iaddr_old, sizeof(iaddr_old), &iport_old, 0, 0,
	                      0, 0,
	                      &timestamp, 0, 0);

			      ...

       	r = get_redirect_rule(ext_if_name, eport, proto_atoi(protocol),
	                      iaddr, iaddrlen, iport, desc, desclen,
	                      rhost, rhostlen, &timestamp,
	                      0, 0);
	if(r == 0 && timestamp > 0 && timestamp > (current_time = time(NULL))) {
			      

	/* remove the rule if no traffic has used it */
	if(get_redirect_rule(ifname, list->eport, list->proto,
                         0, 0, &iport, 0, 0, 0, 0, &timestamp,
	                     &packets, &bytes) >= 0)
	{



{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>
{   1}     upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>
{   1}     remove_unused_rules() <void remove_unused_rules (struct rule_state list) at upnpredirect.c:533>

{   0} get_redirect_rule_by_index():

	if(get_redirect_rule_by_index(index, 0/*ifname*/, eport, iaddr, iaddrlen,
	                              iport, &proto, desc, desclen,
	                              rhost, rhostlen, &timestamp,
	                              0, 0) < 0)
		return -1;
	else

	...

	while(get_redirect_rule_by_index(i, /*ifname*/0, &tmp->eport, 0, 0,
	                              &iport, &proto, 0, 0, 0,0, &timestamp,
								  &tmp->packets, &tmp->bytes) >= 0)
	{


{   1}     upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:
{   2}         upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>
{   1}     write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>

TBD: not usd now.
{   0} get_rule_from_file():
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>

TBD: not used now.
{   0} get_rule_from_leasetime():
{   1}     upnp_update_expiredpinhole() <int upnp_update_expiredpinhole (void) at upnpredirect.c:1071>:
{   2}         upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   3}             upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>
{   2}         upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   3}             upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

this is defined in upnpredirect.c
{   0} get_upnp_rules_state_list() <struct rule_state get_upnp_rules_state_list (int max_rules_number_target) at upnpredirect.c:463>





defined in upnpredirect.c: called from miniupnpd.c
{   0} reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>


{   0} remove_unused_rules() <void remove_unused_rules (struct rule_state list) at upnpredirect.c:533>

TBD: not used for now
{   0} retrieve_packets():
{   1}     upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>

TBD: not used for now
{   0} retrieve_timeout():
{   1}     upnp_check_outbound_pinhole() <int upnp_check_outbound_pinhole (int proto, int *timeout) at upnpredirect.c:582>

TBD: not used for now
{   0} rule_file_add():
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>

TBD: not used for now.
{   0} rule_file_remove():
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

TBD: not used for now 
{   0} rule_file_update():
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>



called from upnpsoap.c: #ifdef ENABLE_6FC_SERVICE
{   0} upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>


#ifdef ENABLE_6FC_SERVICE
{   0} upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>

called from upnpsoap.c: 
{   0} upnp_check_outbound_pinhole() <int upnp_check_outbound_pinhole (int proto, int *timeout) at upnpredirect.c:582>

called from upnpsoap.c:
{   0} upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>

TBD: not called anywhere
{   0} upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

called from upnpsoap.c
{   0} upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   1}     upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

called from upnpsoap.c:
{   0} upnp_delete_redirection() <int upnp_delete_redirection (unsigned short eport, const char *protocol) at upnpredirect.c:433>

Defined in upnpevents.c:
{   0} upnp_event_var_change_notify():
{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>

called from upnpsoap.c:
{   0} upnp_get_pinhole_info() <int upnp_get_pinhole_info (const char *raddr, unsigned short rport, char *iaddr, unsigned short *iport, char *proto, const char *uid, char *lt) at upnpredirect.c:760>

called from upnpsoap.c:
{   0} upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>

called from upnpsoap.c:
{   0} upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>

{   0} upnp_get_portmappings_in_range() <unsigned short *upnp_get_portmappings_in_range (unsigned short startport, unsigned short endport, const char *protocol, unsigned int *number) at upnpredirect.c:568>
/* upnp_get_portmappings_in_range()
 * return a list of all "external" ports for which a port
 * mapping exists */


called from upnpsoap.c:
{   0} upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>

called from upnpsoap.c
{   0} upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:
{   1}     upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>

called from upnpsoap.c and natpmc.c:

{   0} upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>

called from natpmc.c
{   0} upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>

{   0} upnp_update_expiredpinhole() <int upnp_update_expiredpinhole (void) at upnpredirect.c:1071>:
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   1}     upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

{   0} upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>

called from miniupnpd.c
{   0} write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>



make -f Makefile.linux -k cflow
cflow -l -r   \
	upnpredirect.c getifaddr.c  \
	natpmp.c 


grep "0}" output from the above command


{   0} CleanExpiredNATPMP() <int CleanExpiredNATPMP () at natpmp.c:335>

{   0} IN6_IS_ADDR_LINKLOCAL():

{   0} IN6_IS_ADDR_LOOPBACK():

{   0} OpenAndConfNATPMPSocket() <int OpenAndConfNATPMPSocket (in_addr_t addr) at natpmp.c:26>:

{   0} OpenAndConfNATPMPSockets() <int OpenAndConfNATPMPSockets (int *sockets) at natpmp.c:53>

{   0} ProcessIncomingNATPMPPacket() <void ProcessIncomingNATPMPPacket (int s) at natpmp.c:108>

{   0} ScanNATPMPforExpiration() <int ScanNATPMPforExpiration () at natpmp.c:305>:

{   0} SendNATPMPPublicAddressChangeNotification() <void SendNATPMPPublicAddressChangeNotification (int *sockets, int n_sockets) at natpmp.c:365>

{   0} add_filter_rule2():

{   0} add_redirect_rule2():

{   0} check_rule_from_file():

{   0} check_upnp_rule_against_permissions():

{   0} delete_filter_rule():

{   0} delete_redirect_and_filter_rules():

{   0} delete_redirect_rule():

{   0} find_ipv6_addr() <int find_ipv6_addr (const char *ifname, char *dst, int n) at getifaddr.c:104>

{   0} freeifaddrs():

{   0} get_portmappings_in_range():

{   0} get_redirect_rule():

{   0} get_redirect_rule_by_index():

{   0} get_rule_from_file():

{   0} get_rule_from_leasetime():

{   0} get_upnp_rules_state_list() <struct rule_state get_upnp_rules_state_list (int max_rules_number_target) at upnpredirect.c:463>

{   0} getifaddr() <int getifaddr (const char *ifname, char *buf, int len) at getifaddr.c:29>:

{   0} getifaddrs():



{   0} reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>


{   0} remove_unused_rules() <void remove_unused_rules (struct rule_state list) at upnpredirect.c:533>


{   0} retrieve_packets():

{   0} retrieve_timeout():

{   0} rule_file_add():

{   0} rule_file_remove():

{   0} rule_file_update():



{   0} upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>


{   0} upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:


{   0} upnp_check_outbound_pinhole() <int upnp_check_outbound_pinhole (int proto, int *timeout) at upnpredirect.c:582>


{   0} upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>


{   0} upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>


{   0} upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:


{   0} upnp_delete_redirection() <int upnp_delete_redirection (unsigned short eport, const char *protocol) at upnpredirect.c:433>


{   0} upnp_event_var_change_notify():


{   0} upnp_get_pinhole_info() <int upnp_get_pinhole_info (const char *raddr, unsigned short rport, char *iaddr, unsigned short *iport, char *proto, const char *uid, char *lt) at upnpredirect.c:760>


{   0} upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>


{   0} upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>


{   0} upnp_get_portmappings_in_range() <unsigned short *upnp_get_portmappings_in_range (unsigned short startport, unsigned short endport, const char *protocol, unsigned int *number) at upnpredirect.c:568>


{   0} upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>


{   0} upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:


{   0} upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:


{   0} upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:


{   0} upnp_update_expiredpinhole() <int upnp_update_expiredpinhole (void) at upnpredirect.c:1071>:


{   0} upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:


{   0} write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>

========================
cflow -l -r miniupnpd.c upnpredirect.c upnpsoap.c



{   0} LOG_UPTO():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} OpenAndConfInterfaceWatchSocket():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} OpenAndConfNATPMPSockets():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} OpenAndConfSSDPNotifySockets():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} OpenAndConfSSDPReceiveSocket():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ProcessIncomingNATPMPPacket():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ProcessInterfaceWatchNotify():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ProcessSSDPData():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ProcessSSDPRequest():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} Process_upnphttp():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} SETFLAG():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ScanNATPMPforExpiration():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} SendNATPMPPublicAddressChangeNotification():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>


{   0} SubmitServicesToMiniSSDPD():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} check_upnp_rule_against_permissions():
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} delete_filter_rule():

{   0} delete_redirect_and_filter_rules():

{   0} delete_redirect_rule():
{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   4}                 init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   5}                     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   3}             AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   3}             AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} freeaddrinfo():
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} freeoptions():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} getaddrinfo():
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} gethostbyname():
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} getifaddr():
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     GetCommonLinkProperties() <void GetCommonLinkProperties (struct upnphttp h, const char *action) at upnpsoap.c:160>
{   1}     GetExternalIPAddress() <void GetExternalIPAddress (struct upnphttp h, const char *action) at upnpsoap.c:247>

{   0} getifstats():
{   1}     GetTotalBytesSent() <void GetTotalBytesSent (struct upnphttp h, const char *action) at upnpsoap.c:72>
{   1}     GetTotalBytesReceived() <void GetTotalBytesReceived (struct upnphttp h, const char *action) at upnpsoap.c:94>
{   1}     GetTotalPacketsSent() <void GetTotalPacketsSent (struct upnphttp h, const char *action) at upnpsoap.c:116>
{   1}     GetTotalPacketsReceived() <void GetTotalPacketsReceived (struct upnphttp h, const char *action) at upnpsoap.c:138>
{   1}     GetCommonLinkProperties() <void GetCommonLinkProperties (struct upnphttp h, const char *action) at upnpsoap.c:160>

{   0} getnameinfo():
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>

{   0} getpid():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} getsockname():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} gettimeofday():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} htonl():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} htons():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} identify_ip_protocol() <int identify_ip_protocol (char *payload) at miniupnpd.c:174>:
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} if_nametoindex():
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} inet_aton():
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} inet_ntoa():
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} inet_ntop():
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} inet_pton():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} init_redirect():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} isdigit():
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} isspace():
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} kstat_close():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} kstat_data_lookup():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} kstat_lookup():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} kstat_open():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} kstat_read():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} listen():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     OpenAndConfCtlUnixSocket() <int OpenAndConfCtlUnixSocket (const char *path) at miniupnpd.c:323>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} localtime():
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>

{   0} main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} malloc():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>

{   0} memcpy():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:
{   2}         upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>:
{   3}             QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   2}         GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   1}     BuildSendAndCloseSoapResp() <void BuildSendAndCloseSoapResp (struct upnphttp h, const char *body, int bodylen) at upnpsoap.c:31>:
{   2}         GetConnectionTypeInfo() <void GetConnectionTypeInfo (struct upnphttp h, const char *action) at upnpsoap.c:60>
{   2}         GetTotalBytesSent() <void GetTotalBytesSent (struct upnphttp h, const char *action) at upnpsoap.c:72>
{   2}         GetTotalBytesReceived() <void GetTotalBytesReceived (struct upnphttp h, const char *action) at upnpsoap.c:94>
{   2}         GetTotalPacketsSent() <void GetTotalPacketsSent (struct upnphttp h, const char *action) at upnpsoap.c:116>
{   2}         GetTotalPacketsReceived() <void GetTotalPacketsReceived (struct upnphttp h, const char *action) at upnpsoap.c:138>
{   2}         GetCommonLinkProperties() <void GetCommonLinkProperties (struct upnphttp h, const char *action) at upnpsoap.c:160>
{   2}         GetStatusInfo() <void GetStatusInfo (struct upnphttp h, const char *action) at upnpsoap.c:200>
{   2}         GetNATRSIPStatus() <void GetNATRSIPStatus (struct upnphttp h, const char *action) at upnpsoap.c:227>
{   2}         GetExternalIPAddress() <void GetExternalIPAddress (struct upnphttp h, const char *action) at upnpsoap.c:247>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   2}         GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   2}         DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   2}         DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   2}         GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   2}         GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   2}         SetDefaultConnectionService() <void SetDefaultConnectionService (struct upnphttp h, const char *action) at upnpsoap.c:964>
{   2}         GetDefaultConnectionService() <void GetDefaultConnectionService (struct upnphttp h, const char *action) at upnpsoap.c:982>
{   2}         QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   2}         GetFirewallStatus() <void GetFirewallStatus (struct upnphttp h, const char *action) at upnpsoap.c:1112>
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>

{   0} memset():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     parselanaddr() <int parselanaddr (struct lan_addr_s lan_addr, const char *str) at miniupnpd.c:528>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>

{   0} methodImpl() <void (*methodImpl) (struct upnphttp *, const char *) at upnpsoap.c:1746>:
{   1}     ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} mkstemp():
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:

{   0} nfnl_fd():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_bind_pf():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_create_queue():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_get_indev():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_get_msg_packet_hdr():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_get_payload():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_handle_packet():
{   1}     ProcessNFQUEUE() <void ProcessNFQUEUE (int fd) at miniupnpd.c:306>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_nfnlh():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_open():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_set_mode():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_set_verdict():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} nfq_unbind_pf():
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ntohl():
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} ntohs():
{   1}     get_udp_dst_port() <int get_udp_dst_port (char *payload) at miniupnpd.c:182>:
{   2}         nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   3}             OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} open():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} openlog():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} perror():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} printf():
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} rand():
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>

{   0} read():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} readoptionsfile():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} realloc():
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>

{   0} recvfrom():
{   1}     ProcessNFQUEUE() <void ProcessNFQUEUE (int fd) at miniupnpd.c:306>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} remove():
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:

{   0} remove_unused_rules() <void remove_unused_rules (struct rule_state list) at upnpredirect.c:533>:
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} rename():
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:

{   0} retrieve_packets():
{   1}     upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>:
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} retrieve_timeout():
{   1}     upnp_check_outbound_pinhole() <int upnp_check_outbound_pinhole (int proto, int *timeout) at upnpredirect.c:582>:
{   2}         GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>

{   0} rule_file_add():
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>

{   0} rule_file_remove():
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>

{   0} rule_file_update():
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>

{   0} select():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} set_non_blocking():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} setlogmask():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} setsockopt():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} sigaction():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} signal():
{   1}     sigterm() <void sigterm (int sig) at miniupnpd.c:417>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} snprintf():
{   1}     write_upnphttp_details() <void write_upnphttp_details (int fd, struct upnphttp e) at miniupnpd.c:348>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_ctlsockets_list() <void write_ctlsockets_list (int fd, struct ctlelem e) at miniupnpd.c:366>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_option_list() <void write_option_list (int fd) at miniupnpd.c:381>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_command_line() <void write_command_line (int fd, int argc, char **argv) at miniupnpd.c:397>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>:
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   1}     write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     GetTotalBytesSent() <void GetTotalBytesSent (struct upnphttp h, const char *action) at upnpsoap.c:72>
{   1}     GetTotalBytesReceived() <void GetTotalBytesReceived (struct upnphttp h, const char *action) at upnpsoap.c:94>
{   1}     GetTotalPacketsSent() <void GetTotalPacketsSent (struct upnphttp h, const char *action) at upnpsoap.c:116>
{   1}     GetTotalPacketsReceived() <void GetTotalPacketsReceived (struct upnphttp h, const char *action) at upnpsoap.c:138>
{   1}     GetCommonLinkProperties() <void GetCommonLinkProperties (struct upnphttp h, const char *action) at upnpsoap.c:160>
{   1}     GetStatusInfo() <void GetStatusInfo (struct upnphttp h, const char *action) at upnpsoap.c:200>
{   1}     GetExternalIPAddress() <void GetExternalIPAddress (struct upnphttp h, const char *action) at upnpsoap.c:247>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   1}     GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   1}     GetDefaultConnectionService() <void GetDefaultConnectionService (struct upnphttp h, const char *action) at upnpsoap.c:982>
{   1}     QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   1}     GetFirewallStatus() <void GetFirewallStatus (struct upnphttp h, const char *action) at upnpsoap.c:1112>
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>
{   1}     CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   1}     SoapError() <void SoapError (struct upnphttp h, int errCode, const char *errDesc) at upnpsoap.c:1846>:
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   2}         GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   2}         DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   2}         DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   2}         GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   2}         GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   2}         SetConnectionType() <void SetConnectionType (struct upnphttp h, const char *action) at upnpsoap.c:1004>
{   2}         RequestConnection() <void RequestConnection (struct upnphttp h, const char *action) at upnpsoap.c:1019>
{   2}         ForceTermination() <void ForceTermination (struct upnphttp h, const char *action) at upnpsoap.c:1026>
{   2}         QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   2}         CheckStatus() <int CheckStatus (struct upnphttp h) at upnpsoap.c:1131>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   3}             UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   3}             DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   3}             CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   3}             GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         DataVerification() <int DataVerification (struct upnphttp h, char *int_ip, unsigned short *int_port, const char *protocol, char *leaseTime) at upnpsoap.c:1148>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   3}             UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   3}             DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   3}             CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   3}             GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} sockaddr_to_string():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} socket():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     OpenAndConfCtlUnixSocket() <int OpenAndConfCtlUnixSocket (const char *path) at miniupnpd.c:323>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} srand():
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>

{   0} strcat():
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>

{   0} strchr():
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     DataVerification() <int DataVerification (struct upnphttp h, char *int_ip, unsigned short *int_port, const char *protocol, char *leaseTime) at upnpsoap.c:1148>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} strcmp():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     proto_atoi() <int proto_atoi (const char *protocol) at upnpredirect.c:53>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   4}                 init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   5}                     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   3}             AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   3}             AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   2}         upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>:
{   3}             GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   3}             GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   2}         upnp_delete_redirection() <int upnp_delete_redirection (unsigned short eport, const char *protocol) at upnpredirect.c:433>:
{   3}             DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   3}             DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   2}         upnp_get_portmappings_in_range() <unsigned short *upnp_get_portmappings_in_range (unsigned short startport, unsigned short endport, const char *protocol, unsigned int *number) at upnpredirect.c:568>:
{   3}             DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   3}             GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   1}     DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   1}     QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} strcpy():
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     upnp_update_expiredpinhole() <int upnp_update_expiredpinhole (void) at upnpredirect.c:1071>:
{   2}         upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   3}             upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   4}                 AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   3}             UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   3}             upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   3}             DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>

{   0} strftime():
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>

{   0} strlen():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   1}     DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   1}     ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} strncat():
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:

{   0} strncmp():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     connecthostport() <int connecthostport (const char *host, unsigned short port, char *result) at upnpsoap.c:1204>
{   1}     ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} strncpy():
{   1}     OpenAndConfCtlUnixSocket() <int OpenAndConfCtlUnixSocket (const char *path) at miniupnpd.c:323>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     GetExternalIPAddress() <void GetExternalIPAddress (struct upnphttp h, const char *action) at upnpsoap.c:247>

{   0} strstr():
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>

{   0} strtoul():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} sysctl():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} syslog():
{   1}     OpenAndConfHTTPSocket() <int OpenAndConfHTTPSocket (unsigned short port) at miniupnpd.c:102>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     nfqueue_cb() <int nfqueue_cb (struct nfq_q_handle qh, struct nfgenmsg nfmsg, struct nfq_data nfa, void *data) at miniupnpd.c:242>:
{   2}         OpenAndConfNFqueue() <int OpenAndConfNFqueue () at miniupnpd.c:194>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     OpenAndConfCtlUnixSocket() <int OpenAndConfCtlUnixSocket (const char *path) at miniupnpd.c:323>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     sigterm() <void sigterm (int sig) at miniupnpd.c:417>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     sigusr1() <void sigusr1 (int sig) at miniupnpd.c:430>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     lease_file_add() <int lease_file_add (unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:63>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   3}             upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   4}                 reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   5}                     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   6}                         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   4}                 AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   4}                 AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     lease_file_remove() <int lease_file_remove (unsigned short eport, int proto) at upnpredirect.c:89>:
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     upnp_delete_redirection() <int upnp_delete_redirection (unsigned short eport, const char *protocol) at upnpredirect.c:433>:
{   2}         DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   2}         DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   1}     remove_unused_rules() <void remove_unused_rules (struct rule_state list) at upnpredirect.c:533>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     GetExternalIPAddress() <void GetExternalIPAddress (struct upnphttp h, const char *action) at upnpsoap.c:247>
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   1}     DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   1}     GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   1}     SetDefaultConnectionService() <void SetDefaultConnectionService (struct upnphttp h, const char *action) at upnpsoap.c:964>
{   1}     QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   1}     DataVerification() <int DataVerification (struct upnphttp h, char *int_ip, unsigned short *int_port, const char *protocol, char *leaseTime) at upnpsoap.c:1148>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   1}     AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   1}     GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>
{   1}     DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   1}     CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>
{   1}     SoapError() <void SoapError (struct upnphttp h, int errCode, const char *errDesc) at upnpsoap.c:1846>:
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   2}         GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   2}         DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   2}         DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   2}         GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   2}         GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   2}         SetConnectionType() <void SetConnectionType (struct upnphttp h, const char *action) at upnpsoap.c:1004>
{   2}         RequestConnection() <void RequestConnection (struct upnphttp h, const char *action) at upnpsoap.c:1019>
{   2}         ForceTermination() <void ForceTermination (struct upnphttp h, const char *action) at upnpsoap.c:1026>
{   2}         QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   2}         CheckStatus() <int CheckStatus (struct upnphttp h) at upnpsoap.c:1131>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   3}             UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   3}             DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   3}             CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   3}             GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         DataVerification() <int DataVerification (struct upnphttp h, char *int_ip, unsigned short *int_port, const char *protocol, char *leaseTime) at upnpsoap.c:1148>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         PinholeVerification() <int PinholeVerification (struct upnphttp h, char *int_ip, unsigned short *int_port) at upnpsoap.c:1259>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   3}             UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   3}             DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   3}             CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   3}             GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   2}         GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   2}         GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>
{   2}         ExecuteSoapAction() <void ExecuteSoapAction (struct upnphttp h, const char *action, int n) at upnpsoap.c:1792>

{   0} system():
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>

{   0} time():
{   1}     set_startup_time() <void set_startup_time (int sysuptime) at miniupnpd.c:439>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>
{   1}     upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>:
{   2}         GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   2}         GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>
{   1}     upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:
{   2}         upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>:
{   3}             QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   2}         GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   2}         CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     GetStatusInfo() <void GetStatusInfo (struct upnphttp h, const char *action) at upnpsoap.c:200>

{   0} unlink():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   1}     AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>

{   0} upnp_add_inboundpinhole_internal() <int upnp_add_inboundpinhole_internal (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *proto, int *uid) at upnpredirect.c:693>:
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>

{   0} upnp_check_outbound_pinhole() <int upnp_check_outbound_pinhole (int proto, int *timeout) at upnpredirect.c:582>:
{   1}     GetOutboundPinholeTimeout() <void GetOutboundPinholeTimeout (struct upnphttp h, const char *action) at upnpsoap.c:1456>

{   0} upnp_check_pinhole_working() <int upnp_check_pinhole_working (const char *uid, char *eaddr, char *iaddr, unsigned short *eport, unsigned short *iport, char *protocol, int *rulenum_used) at upnpredirect.c:842>:
{   1}     CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>

{   0} upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

{   0} upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   1}     upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   1}     DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>

{   0} upnp_delete_redirection() <int upnp_delete_redirection (unsigned short eport, const char *protocol) at upnpredirect.c:433>:
{   1}     DeletePortMapping() <void DeletePortMapping (struct upnphttp h, const char *action) at upnpsoap.c:648>
{   1}     DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>

{   0} upnp_event_var_change_notify():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   2}         upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   3}             reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   4}                 init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   5}                     main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   3}             AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   3}             AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} upnp_get_pinhole_info() <int upnp_get_pinhole_info (const char *raddr, unsigned short rport, char *iaddr, unsigned short *iport, char *proto, const char *uid, char *lt) at upnpredirect.c:760>:
{   1}     UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   1}     DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   1}     CheckPinholeWorking() <void CheckPinholeWorking (struct upnphttp h, const char *action) at upnpsoap.c:1568>
{   1}     GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} upnp_get_pinhole_packets() <int upnp_get_pinhole_packets (const char *uid, int *packets) at upnpredirect.c:1051>:
{   1}     GetPinholePackets() <void GetPinholePackets (struct upnphttp h, const char *action) at upnpsoap.c:1666>

{   0} upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>:
{   1}     QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>

{   0} upnp_get_portmappings_in_range() <unsigned short *upnp_get_portmappings_in_range (unsigned short startport, unsigned short endport, const char *protocol, unsigned int *number) at upnpredirect.c:568>:
{   1}     DeletePortMappingRange() <void DeletePortMappingRange (struct upnphttp h, const char *action) at upnpsoap.c:709>
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>

{   0} upnp_get_redirection_infos() <int upnp_get_redirection_infos (unsigned short eport, const char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:347>:
{   1}     GetSpecificPortMappingEntry() <void GetSpecificPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:571>
{   1}     GetListOfPortMappings() <void GetListOfPortMappings (struct upnphttp h, const char *action) at upnpsoap.c:822>

{   0} upnp_get_redirection_infos_by_index() <int upnp_get_redirection_infos_by_index (int index, unsigned short *eport, char *protocol, unsigned short *iport, char *iaddr, int iaddrlen, char *desc, int desclen, char *rhost, int rhostlen, unsigned int *leaseduration) at upnpredirect.c:375>:
{   1}     upnp_get_portmapping_number_of_entries() <int upnp_get_portmapping_number_of_entries () at upnpredirect.c:442>:
{   2}         QueryStateVariable() <void QueryStateVariable (struct upnphttp h, const char *action) at upnpsoap.c:1040>
{   1}     GetGenericPortMappingEntry() <void GetGenericPortMappingEntry (struct upnphttp h, const char *action) at upnpsoap.c:755>

{   0} upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   1}     reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   2}         init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   3}             main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   1}     AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} upnp_redirect_internal() <int upnp_redirect_internal (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, int proto, const char *desc, unsigned int timestamp) at upnpredirect.c:307>:
{   1}     upnp_redirect() <int upnp_redirect (const char *rhost, unsigned short eport, const char *iaddr, unsigned short iport, const char *protocol, const char *desc, unsigned int leaseduration) at upnpredirect.c:256>:
{   2}         reload_from_lease_file() <int reload_from_lease_file () at upnpredirect.c:149>:
{   3}             init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   4}                 main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   2}         AddPortMapping() <void AddPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:294>
{   2}         AddAnyPortMapping() <void AddAnyPortMapping (struct upnphttp h, const char *action) at upnpsoap.c:445>

{   0} upnp_update_expiredpinhole() <int upnp_update_expiredpinhole (void) at upnpredirect.c:1071>:
{   1}     upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   2}         upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   3}             AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   2}         UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>
{   1}     upnp_delete_inboundpinhole() <int upnp_delete_inboundpinhole (const char *uid) at upnpredirect.c:795>:
{   2}         upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>
{   2}         DeletePinhole() <void DeletePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1509>
{   1}     upnp_clean_expiredpinhole() <int upnp_clean_expiredpinhole () at upnpredirect.c:1091>

{   0} upnp_update_inboundpinhole() <int upnp_update_inboundpinhole (const char *uid, const char *leasetime) at upnpredirect.c:774>:
{   1}     upnp_add_inboundpinhole() <int upnp_add_inboundpinhole (const char *raddr, unsigned short rport, const char *iaddr, unsigned short iport, const char *protocol, const char *leaseTime, int *uid) at upnpredirect.c:631>:
{   2}         AddPinhole() <void AddPinhole (struct upnphttp h, const char *action) at upnpsoap.c:1330>
{   1}     UpdatePinhole() <void UpdatePinhole (struct upnphttp h, const char *action) at upnpsoap.c:1399>

{   0} upnpevents_processfds():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} upnpevents_selectfds():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} write():
{   1}     write_upnphttp_details() <void write_upnphttp_details (int fd, struct upnphttp e) at miniupnpd.c:348>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_ctlsockets_list() <void write_ctlsockets_list (int fd, struct ctlelem e) at miniupnpd.c:366>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_option_list() <void write_option_list (int fd) at miniupnpd.c:381>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_command_line() <void write_command_line (int fd, int argc, char **argv) at miniupnpd.c:397>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
{   1}     write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} write_events_details():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} write_permlist():
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} write_ruleset_details() <void write_ruleset_details (int s) at upnpredirect.c:1105>:
{   1}     main() <int main (int argc, char **argv) at miniupnpd.c:1123>

{   0} writepidfile():
{   1}     init() <int init (int argc, char **argv, struct runtime_vars v) at miniupnpd.c:631>:
{   2}         main() <int main (int argc, char **argv) at miniupnpd.c:1123>
===

{   0} OpenAndConfInterfaceWatchSocket():
{   0} ProcessInterfaceWatchNotify():

{   0} add_filter_rule2():
{   0} add_redirect_rule2():

{   0} check_rule_from_file():

{   0} delete_filter_rule():
{   0} delete_redirect_and_filter_rules():
{   0} delete_redirect_rule():

{   0} freeaddrinfo():
{   0} freeifaddrs():

{   0} get_portmappings_in_range():
{   0} get_redirect_rule():
{   0} get_redirect_rule_by_index():
{   0} get_rule_from_file():
{   0} get_rule_from_leasetime():


{   0} if_nametoindex():

{   0} init_redirect():

{   0} kstat_close():
{   0} kstat_data_lookup():
{   0} kstat_lookup():
{   0} kstat_open():
{   0} kstat_read():

{   0} link_ntoa():

{   0} nfnl_fd():

{   0} nfq_bind_pf():
{   0} nfq_create_queue():
{   0} nfq_get_indev():
{   0} nfq_get_msg_packet_hdr():
{   0} nfq_get_payload():
{   0} nfq_handle_packet():
{   0} nfq_nfnlh():
{   0} nfq_open():
{   0} nfq_set_mode():
{   0} nfq_set_verdict():
{   0} nfq_unbind_pf():

{   0} retrieve_packets():
{   0} retrieve_timeout():

{   0} rule_file_add():
{   0} rule_file_remove():
{   0} rule_file_update():

