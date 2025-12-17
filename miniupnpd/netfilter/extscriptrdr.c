/* $Id$ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * External script wrapper for port forwarding operations
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include "../config.h"
#include "../upnpglobalvars.h"
#include "extscriptrdr.h"

/* proto_itoa()
 * convert IPPROTO_TCP or IPPROTO_UDP to string */
static const char *
proto_itoa(int proto)
{
	switch(proto) {
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
#ifdef IPPROTO_UDPLITE
	case IPPROTO_UDPLITE:
		return "UDPLITE";
#endif
	default:
		return "*";
	}
}

/* execute_external_script()
 * Execute the external script with given parameters
 * Returns: 0 on success, -1 on error */
static int execute_external_script(const char *operation, const char **args, int arg_count) {
	pid_t pid;
	int status;
	
	syslog(LOG_ERR, "execute_external_script called: operation=%s, arg_count=%d", operation, arg_count);
	
	if (!external_script_path || strlen(external_script_path) == 0) {
		syslog(LOG_ERR, "external script path not configured");
		return -1;
	}
	
	syslog(LOG_ERR, "external_script_path is: %s", external_script_path);
	
	/* Check if script exists and is executable */
	if (access(external_script_path, X_OK) != 0) {
		syslog(LOG_ERR, "external script not found or not executable: %s (%m)", external_script_path);
		return -1;
	}
	
	syslog(LOG_ERR, "external script found and executable: %s, operation: %s", external_script_path, operation);
	
	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "fork() failed: %m");
		return -1;
	}

	if (pid == 0) {
		/* Child process */
		int test_errno;
		
		/* Test file access BEFORE anything else */
		test_errno = access("/bin/bash", X_OK);
		syslog(LOG_ERR, "CHILD: access(/bin/bash) = %d, errno=%d", test_errno, errno);
		
		test_errno = access(external_script_path, R_OK);
		syslog(LOG_ERR, "CHILD: access(%s) = %d, errno=%d", external_script_path, test_errno, errno);
		
		/* Build full argv for bash: bash, script_path, operation, arg1, arg2, ..., NULL */
		char **argv = malloc(sizeof(char*) * (arg_count + 4));
		if (!argv) {
			syslog(LOG_ERR, "CHILD: malloc failed");
			exit(1);
		}

		argv[0] = "/bin/bash";
		argv[1] = (char*)external_script_path;
		argv[2] = (char*)operation;
		for (int i = 0; i < arg_count; i++) {
			argv[i + 3] = (char*)args[i];
		}
		argv[arg_count + 3] = NULL;

		syslog(LOG_ERR, "CHILD: about to execve /bin/bash");
		
		/* Build minimal environment */
		char *envp[] = {
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"SHELL=/bin/bash",
			NULL
		};
		
		/* Close syslog RIGHT before exec */
		closelog();
		
		/* Execute bash with script and all arguments */
		execve("/bin/bash", argv, envp);
		
		/* If we get here, exec failed */
		openlog("miniupnpd", LOG_PID | LOG_CONS, LOG_DAEMON);
		syslog(LOG_ERR, "CHILD: execve failed: errno=%d", errno);
		exit(254);
	}

	/* Parent process */
	syslog(LOG_ERR, "parent: waiting for child process %d", pid);
	if (waitpid(pid, &status, 0) == -1) {
		syslog(LOG_ERR, "waitpid() failed: %m");
		return -1;
	}

	syslog(LOG_ERR, "parent: child finished, status=%d", status);

	if (WIFEXITED(status)) {
		int exit_code = WEXITSTATUS(status);
		syslog(LOG_ERR, "external script exited with code %d", exit_code);
		if (exit_code != 0) {
			syslog(LOG_ERR, "external script failed with code %d", exit_code);
			return -1;
		}
		return 0;
	} else if (WIFSIGNALED(status)) {
		syslog(LOG_ERR, "external script killed by signal %d", WTERMSIG(status));
		return -1;
	}

	syslog(LOG_ERR, "external script finished with unknown status %d", status);
	return -1;
}

/* ext_add_redirect_rule2()
 * Add port forwarding rule using external script
 * Script is called as: script add_redirect ifname rhost eport iaddr iport proto desc timestamp */
int
ext_add_redirect_rule2(const char * ifname,
                       const char * rhost, unsigned short eport,
                       const char * iaddr, unsigned short iport, int proto,
                       const char * desc, unsigned int timestamp)
{
	char eport_str[6];
	char iport_str[6];
	char timestamp_str[16];
	const char * args[8];
	int arg_count = 0;

	snprintf(eport_str, sizeof(eport_str), "%hu", eport);
	snprintf(iport_str, sizeof(iport_str), "%hu", iport);
	snprintf(timestamp_str, sizeof(timestamp_str), "%u", timestamp);

	args[arg_count++] = ifname ? ifname : "";
	args[arg_count++] = rhost ? rhost : "*";
	args[arg_count++] = eport_str;
	args[arg_count++] = iaddr;
	args[arg_count++] = iport_str;
	args[arg_count++] = proto_itoa(proto);
	args[arg_count++] = desc ? desc : "";
	args[arg_count++] = timestamp_str;

	syslog(LOG_ERR, "ext_add_redirect_rule2: %s %s:%s -> %s:%s %s",
	       proto_itoa(proto), rhost ? rhost : "*", eport_str, iaddr, iport_str, desc ? desc : "");

	return execute_external_script("add_redirect", args, arg_count);
}

/* ext_add_filter_rule2()
 * Add filter rule using external script
 * Script is called as: script add_filter ifname rhost iaddr eport iport proto desc */
int
ext_add_filter_rule2(const char * ifname,
                     const char * rhost, const char * iaddr,
                     unsigned short eport, unsigned short iport,
                     int proto, const char * desc)
{
	char eport_str[6];
	char iport_str[6];
	const char * args[7];
	int arg_count = 0;

	snprintf(eport_str, sizeof(eport_str), "%hu", eport);
	snprintf(iport_str, sizeof(iport_str), "%hu", iport);

	args[arg_count++] = ifname ? ifname : "";
	args[arg_count++] = rhost ? rhost : "*";
	args[arg_count++] = iaddr;
	args[arg_count++] = eport_str;
	args[arg_count++] = iport_str;
	args[arg_count++] = proto_itoa(proto);
	args[arg_count++] = desc ? desc : "";

	syslog(LOG_ERR, "ext_add_filter_rule2: %s %s %s:%s -> %s:%s",
	       proto_itoa(proto), rhost ? rhost : "*", ifname, eport_str, iaddr, iport_str);

	return execute_external_script("add_filter", args, arg_count);
}

/* ext_delete_redirect_rule()
 * Delete port forwarding rule using external script
 * Script is called as: script delete_redirect ifname eport proto */
int
ext_delete_redirect_rule(const char * ifname, unsigned short eport, int proto)
{
	char eport_str[6];
	const char * args[3];
	int arg_count = 0;

	snprintf(eport_str, sizeof(eport_str), "%hu", eport);

	args[arg_count++] = ifname ? ifname : "";
	args[arg_count++] = eport_str;
	args[arg_count++] = proto_itoa(proto);

	syslog(LOG_ERR, "ext_delete_redirect_rule: %s %s:%s",
	       proto_itoa(proto), ifname, eport_str);

	return execute_external_script("delete_redirect", args, arg_count);
}

/* ext_delete_filter_rule()
 * Delete filter rule using external script
 * Script is called as: script delete_filter ifname eport proto */
int
ext_delete_filter_rule(const char * ifname, unsigned short eport, int proto)
{
	char eport_str[6];
	const char * args[3];
	int arg_count = 0;

	snprintf(eport_str, sizeof(eport_str), "%hu", eport);

	args[arg_count++] = ifname ? ifname : "";
	args[arg_count++] = eport_str;
	args[arg_count++] = proto_itoa(proto);

	syslog(LOG_ERR, "ext_delete_filter_rule: %s %s:%s",
	       proto_itoa(proto), ifname, eport_str);

	return execute_external_script("delete_filter", args, arg_count);
}

/* ext_delete_redirect_and_filter_rules()
 * Delete both redirect and filter rules
 * Script is called as: script delete_redirect_and_filter ifname eport proto */
int
ext_delete_redirect_and_filter_rules(unsigned short eport, int proto)
{
	char eport_str[6];
	const char * args[2];
	int arg_count = 0;

	snprintf(eport_str, sizeof(eport_str), "%hu", eport);

	args[arg_count++] = eport_str;
	args[arg_count++] = proto_itoa(proto);

	syslog(LOG_ERR, "ext_delete_redirect_and_filter_rules: %s :%s",
	       proto_itoa(proto), eport_str);

	return execute_external_script("delete_redirect_and_filter", args, arg_count);
}
