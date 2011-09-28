/* $Id: listifaces.c,v 1.4 2007/09/23 16:59:02 nanard Exp $ */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void printhex(const unsigned char * p, int n)
{
	int i;
	while(n>0)
	{
		for(i=0; i<16; i++)
			printf("%02x ", p[i]);
		printf("| ");
		for(i=0; i<16; i++)
		{
			putchar((p[i]>=32 && p[i]<127)?p[i]:'.');
		}
		printf("\n");
		p+=16;
		n -= 16;
	}
}

void listifaces()
{
	struct ifconf ifc;
	char * buf = 0;
	int buflen = sizeof(struct ifreq)*20;
	/*[sizeof(struct ifreq)*8];*/
	int s, i;
	int j;
	char saddr[256/*INET_ADDRSTRLEN*/];
	/*s = socket(PF_INET, SOCK_DGRAM, 0);*/
	s = socket(AF_INET, SOCK_DGRAM, 0);
	do {
		buflen += buflen;
		buf = realloc(buf, buflen);
		ifc.ifc_len = buflen;
		ifc.ifc_buf = (caddr_t)buf;
		if(ioctl(s, SIOCGIFCONF, &ifc) < 0)
		{
			perror("ioctl");
			close(s);
			free(buf);
			return;
		}
		printf("%d - %d - %d\n", buflen, ifc.ifc_len, (int)sizeof(struct ifreq));
		printf(" %d\n", IFNAMSIZ);
		printf(" %d %d\n", (int)sizeof(struct sockaddr), (int)sizeof(struct sockaddr_in) );
	} while(buflen == ifc.ifc_len);
	printhex((const unsigned char *)ifc.ifc_buf, ifc.ifc_len);
	j = 0;
	for(i=0; i<ifc.ifc_len; /*i += sizeof(struct ifreq)*/)
	{
		//const struct ifreq * ifrp = &(ifc.ifc_req[j]);
		const struct ifreq * ifrp = (const struct ifreq *)(buf + i);
		i += sizeof(ifrp->ifr_name) + 16;//ifrp->ifr_addr.sa_len;
		/*inet_ntop(AF_INET, &(((struct sockaddr_in *)&(ifrp->ifr_addr))->sin_addr), saddr, sizeof(saddr));*/
		saddr[0] = '\0';
		inet_ntop(ifrp->ifr_addr.sa_family, &(ifrp->ifr_addr.sa_data[2]), saddr, sizeof(saddr));
		printf("%2d %d %d %s %s\n", j, ifrp->ifr_addr.sa_family, -1/*ifrp->ifr_addr.sa_len*/, ifrp->ifr_name, saddr);
		j++;
	}
	free(buf);
	close(s);
}

int main(int argc, char * * argv)
{
	listifaces();
	return 0;
}

