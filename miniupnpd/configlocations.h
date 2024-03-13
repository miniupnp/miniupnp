#ifndef _MINIUPNPD_CONFIGLOCATIONS_H
#define _MINIUPNPD_CONFIGLOCATIONS_H

#include <stddef.h>

#define CONFIG_RECURSION_DEPTH 5



/* Locations */

struct ConfigLocations *
ConfigLocations_create();
int 
ConfigLocations_close(struct ConfigLocations * locations);
int 
ConfigLocations_free(struct ConfigLocations * locations);
int 
ConfigLocations_open_file(struct ConfigLocations * locations, 
                          const char * path, int debug_flag);
int 
ConfigLocations_open_folder(struct ConfigLocations * locations,
                            const char * path, int debug_flag);
int 
ConfigLocations_open_glob(struct ConfigLocations * locations,
                          const char * pattern, int debug_flag);
char *
ConfigLocations_fgets(struct ConfigLocations * locations,
                      char * line, size_t line_length,
                      const char ** filepath, int * line_number,
                      int debug_flag);

#endif