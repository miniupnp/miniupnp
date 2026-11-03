/* MiniUPnP project
 * PCP MAP FILTER policy : the rules shared by the firewall backends.
 * This software is subject to the conditions detailed in the LICENCE file.
 */
#include "config.h"
#include <string.h>
#include <netinet/in.h>

#include "pcp_filter.h"

#ifdef PCP_FILTER_SUPPORTED

/* set to zero the bits of the address after the prefix */
void
pcp_filter_mask(struct in6_addr * a, unsigned int prefix)
{
	unsigned int i;
	for(i = 0; i < 16; i++, prefix = prefix >= 8 ? prefix - 8 : 0)
		a->s6_addr[i] &= prefix >= 8 ? 255 : (255 << (8 - prefix)) & 255;
}

/* same prefix, port and network ? */
int
pcp_filter_equal(const struct pcp_filter * a, const struct pcp_filter * b)
{
	struct in6_addr x = a->address, y = b->address;
	if(a->prefix != b->prefix || a->port != b->port)
		return 0;
	pcp_filter_mask(&x, a->prefix);
	pcp_filter_mask(&y, b->prefix);
	return memcmp(&x, &y, sizeof(x)) == 0;
}

/* merge the options of a request in the peers of a mapping (RFC 6887
 * section 13.3) : a FILTER with a prefix length of 0 removes all the peers,
 * the others are added (once). v4 : the peers of an IPv4 mapping.
 * returns 0, -1 (invalid) or -2 (too many peers) */
int
pcp_filter_merge(struct pcp_filter * peers, unsigned int * npeers,
                 const struct pcp_filter * options, unsigned int count, int v4)
{
	unsigned int i, j;
	struct pcp_filter f;
	for(i = 0; i < count; i++)
	{
		if(!options[i].prefix)
		{
			*npeers = 0;
			continue;
		}
		f = options[i];
		if(v4 ? (!IN6_IS_ADDR_V4MAPPED(&f.address) || f.prefix < 96) :
		       (IN6_IS_ADDR_V4MAPPED(&f.address) || f.prefix > 128))
			return -1;
		/* canonicalize the unused suffix bits before deduplicating */
		pcp_filter_mask(&f.address, f.prefix);
		for(j = 0; j < *npeers; ++j)
		{
			if(pcp_filter_equal(&peers[j], &f))
				break;
		}
		if(j != *npeers)
			continue;
		if(*npeers == PCP_FILTER_PEER_MAX)
			return -2;
		peers[(*npeers)++] = f;
	}
	return 0;
}

#endif /* PCP_FILTER_SUPPORTED */

/* keep the translation unit non empty */
typedef int pcp_filter_unit_t;
