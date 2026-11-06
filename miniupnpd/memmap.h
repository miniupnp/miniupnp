/* Keeps lease_table.c up to date from the code of the protocols. */
#ifndef MEMMAP_H_INCLUDED
#define MEMMAP_H_INCLUDED

/* an IPv4 mapping was added, or updated (added if unknown) */
void memmap_map(const char * rhost, unsigned short eport, const char * iaddr,
                unsigned short iport, int proto, const char * desc,
                unsigned int timestamp);
void memmap_map_gone(unsigned short eport, int proto);

#endif
