/* $Id: testipfrdr.c,v 1.3 2007/10/01 16:21:23 nanard Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/types.h>
#include "ipfrdr.h"

/* test program for ipfrdr.c */

int runtime_flags = 0;

int
main(int argc, char * * argv)
{
	char c;
	
	openlog("testipfrdrd", LOG_CONS|LOG_PERROR, LOG_USER);
	if(init_redirect() < 0)
	{
		fprintf(stderr, "init_redirect() failed\n");
		return 1;
	}
	
	printf("Add redirection !\n");
	add_redirect_rule2("xennet0", "*", 12345, "192.168.1.100", 54321, IPPROTO_UDP);
	add_redirect_rule2("xennet0", "8.8.8.8", 12345, "192.168.1.100", 54321, IPPROTO_TCP);
	
	printf("Check redirect rules with \"ipnat -l\" then press any key.\n");
	c = getchar();
	
	printf("Delete redirection !\n");
	delete_redirect_rule("xennet0", 12345, IPPROTO_UDP);
	delete_redirect_rule("xennet0", 12345, IPPROTO_TCP);
	
	return 0;
}

