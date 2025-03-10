#include "configlocations.h"

#include <dirent.h>
#include <stdio.h>
#include <glob.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "macros.h"

enum ConfigLocationType
{
    CONFIGLOCATION_FILE,
    CONFIGLOCATION_FOLDER,
    CONFIGLOCATION_GLOB
};

struct ConfigLocationFile
{
    enum ConfigLocationType location_type;
    char * file_path;
    int line_number;
    FILE *handle;
};

struct ConfigLocationFolder
{
    enum ConfigLocationType location_type;
    char * folder_path;
    struct dirent **entries;
    int num_entries;
    int current;
};

struct ConfigLocationGlob
{
    enum ConfigLocationType location_type;
    char * pattern;
    glob_t glob;
    size_t current;
};

union ConfigLocation
{
    enum ConfigLocationType location_type;
    struct ConfigLocationFile file;
    struct ConfigLocationFolder folder;
    struct ConfigLocationGlob glob;
};


struct ConfigLocations
{
    union ConfigLocation locations[CONFIG_RECURSION_DEPTH];
    int depth;
};


int
str_alloc_copy(char ** destination, const char * source)
{
    char * result;
    if (!source)
    {
        return 0;
    }
    result = malloc(strlen(source)+1);
    if (!result){
        return -1;
    }
    strcpy(result, source);
    *destination = result;
    return 0;
}



/** File locations
 * 
 */
int ConfigLocationFile_open(struct ConfigLocationFile * filelocation,
                            const char * path, int debug_flag)
{
    filelocation->location_type = CONFIGLOCATION_FILE;
    
    filelocation->handle = fopen(path, "r");
    if (!filelocation->handle)
    {
        INIT_PRINT_ERR("failed to open file %s: %s", path, strerror(errno));
        return -1;
    }

    if (str_alloc_copy(&(filelocation->file_path), path) == -1)
    {
        INIT_PRINT_ERR("memory allocation error, opening file %s", path);
        fclose(filelocation->handle);
        return -1;
    }
    filelocation->line_number=0;
    return 0;
}


int
ConfigLocationFile_close(struct ConfigLocationFile * filelocation)
{
    fclose(filelocation->handle);
    filelocation->handle = NULL;

    free(filelocation->file_path);
    filelocation->file_path = NULL;

    return 0;
};

int
ConfigLocationFile_isfile(struct ConfigLocationFile * filelocation)
{
    struct stat filestat;
    int fd = fileno(filelocation->handle);
    if (fstat(
        fileno(filelocation->handle),
        &filestat
    ))
    {
        return -1;
    }

    if (S_ISREG(filestat.st_mode))
    {
        return 1;
    }
    return 0;
}

int
ConfigLocationFile_feof(struct ConfigLocationFile *filelocation) {
    return feof(filelocation->handle);
}

char *
ConfigLocationFile_fgets(struct ConfigLocationFile *filelocation, char *line, size_t line_length, const char **file_path, int *line_number){
    char * r;
    r = fgets(line, line_length, filelocation->handle);
    if (r)
    {
        *file_path = filelocation->file_path;
        *line_number = ++filelocation->line_number;
    }
    return r;
}

/** Folder locations
 * 
 */
int
ConfigLocationFolder_filefilter(const struct dirent * entry)
{
    if (entry->d_type != DT_LNK && entry->d_type != DT_REG)
    {
        return 0; // We only want files or symlinks
    }
    if (entry->d_name[0]=='.')
    {
        return 0; // Won't pass dot files
    }
    return 1; // Pass everything else?
}


int
ConfigLocationFolder_open(struct ConfigLocationFolder * folderlocation,
                          const char * path, int debug_flag)
{

    folderlocation->location_type = CONFIGLOCATION_FOLDER;

    if (str_alloc_copy(&(folderlocation->folder_path), path) == -1)
    {
        INIT_PRINT_ERR("memory allocation error, opening folder %s", path);
        return -1;
    }

    folderlocation->num_entries = scandir(
        path,
        &(folderlocation->entries),
        ConfigLocationFolder_filefilter,
        alphasort
    );

    if (folderlocation->num_entries == -1)
    {
        INIT_PRINT_ERR("failed to open folder %s: %s", path, strerror(errno));
        free(folderlocation->folder_path);
        return -1;
    }

    folderlocation->current = -1;
    return 0;
}

int
ConfigLocationFolder_close(struct ConfigLocationFolder * folderlocation)
{
    free(folderlocation->folder_path);
    folderlocation->folder_path = NULL;

    for (int i=0;i<folderlocation->num_entries;++i)
    {
        free(folderlocation->entries[i]);
    }
    free(folderlocation->entries);

    folderlocation->entries = NULL;
    return 0;
};


int
ConfigLocationFolder_alloc_file_path(const struct ConfigLocationFolder * folderlocation,
                                     char ** path, int debug_flag)
{
    int total_len;
    char *result;

    total_len = strlen(folderlocation->folder_path) + 1 + strlen(folderlocation->entries[folderlocation->current]->d_name);

    if (!(result = (char *)malloc(total_len+1)))
    {
        INIT_PRINT_ERR("memory allocation error, opening file %s/%s", folderlocation->folder_path,folderlocation->entries[folderlocation->current]->d_name);
        return -1;
    }

    strncpy(result,folderlocation->folder_path,total_len);
    strncat(result, "/",total_len);
    strncat(result, folderlocation->entries[folderlocation->current]->d_name,total_len);
    result[total_len] = 0;

    *path = result;
    return 0;
}


int
ConfigLocationFolder_nextfilepath(struct ConfigLocationFolder * folderlocation,
                                  char ** next_path, int debug_flag)
{
    char * path;

    if (folderlocation->current == folderlocation->num_entries || ++folderlocation->current == folderlocation->num_entries)
    {
        *next_path = NULL;
        return 0;
    }

    if (ConfigLocationFolder_alloc_file_path(folderlocation, &path, debug_flag))
    {
        return -1;
    }

    *next_path = path;
    return 0;
}

/** Glob locations
 * 
 */
int
ConfigLocationGlob_open(struct ConfigLocationGlob * globlocation,
                        const char * pattern, int debug_flag)
{
    int r;
    globlocation->location_type = CONFIGLOCATION_GLOB;

    if (str_alloc_copy(&(globlocation->pattern), pattern) == -1)
    {
        INIT_PRINT_ERR("memory allocation error, opening pattern %s", pattern);
        return -1;
    }

    r = glob(
        pattern,
        GLOB_ERR|GLOB_MARK,
        NULL,
        &(globlocation->glob)
    );

    if (r)
    {
        INIT_PRINT_ERR("failed find files %s: %s", pattern, strerror(errno));
        globfree(&(globlocation->glob));
        return r;
    }
    globlocation->current = -1;
    return 0;
}

int
ConfigLocationGlob_close(struct ConfigLocationGlob * globlocation)
{
    globfree(&(globlocation->glob));
    return 0;
};


int
ConfigLocationGlob_alloc_file_path(const struct ConfigLocationGlob * globlocation,
                                   char ** path, int debug_flag)
{
    int total_len;
    char * result;
    if (str_alloc_copy(path, globlocation->glob.gl_pathv[globlocation->current]))
    {
        INIT_PRINT_ERR("memory allocation error, opening file %s", globlocation->glob.gl_pathv[globlocation->current]);
        return -1;
    }
    return 0;
}


int
ConfigLocationGlob_nextfilepath(struct ConfigLocationGlob * globlocation,
                                char ** next_path, int debug_flag)
{
    for(++globlocation->current; globlocation->current <globlocation->glob.gl_pathc; ++globlocation->current)
    {
        char * p = globlocation->glob.gl_pathv[globlocation->current];
        if (p[strlen(p)] == '/') // Ends with a '/' means folder
        {
            continue; // This file is a folder apparently
        }
        return ConfigLocationGlob_alloc_file_path(globlocation, next_path, debug_flag);
    }
    *next_path = NULL;
    return 0;
}




/** Locations
 * 
 */

struct ConfigLocations *
ConfigLocations_create()
{
    struct ConfigLocations * locations = malloc(sizeof(struct ConfigLocations));
    locations->depth = -1;
    return locations;
};




int
ConfigLocation_close(union ConfigLocation * location)
{
    if (location == NULL)
    {
        return 0;
    }

    switch(location->location_type)
    {
        case CONFIGLOCATION_FILE:
            return ConfigLocationFile_close(&(location->file));
        case CONFIGLOCATION_FOLDER:
            return ConfigLocationFolder_close(&(location->folder));
        case CONFIGLOCATION_GLOB:
            return ConfigLocationGlob_close(&(location->glob));
    }
    return -1;
};  

int
ConfigLocations_close(struct ConfigLocations *locations)
{
    if (locations->depth < 0)
    {
        return -1;
    }
    int r = (ConfigLocation_close(&(locations->locations[locations->depth])));
    locations->depth--;
    return r;
};

int
ConfigLocations_free(struct ConfigLocations * locations)
{
    if (locations == NULL)
    {
        return -1;
    }
    while (locations->depth > -1)
    {
        int r = ConfigLocations_close(locations);
        if (r != 0) return r;
    }
    free(locations);
    return 0;
};



int
ConfigLocations_check_free_slots(const struct ConfigLocations * locations,
                                 const char * path, int debug_flag)
{
    if (locations->depth >= CONFIG_RECURSION_DEPTH)
    {
        INIT_PRINT_ERR("too many files opened, opening %s",path);
        return -1; // Too many files open
    }
    return 0;
}


int
ConfigLocations_open_file(struct ConfigLocations * locations,
                          const char * path, int debug_flag)
{
    int r;
    
    r = ConfigLocations_check_free_slots(locations, path, debug_flag);
    if (r)
    {
        return r;
    }

    r = ConfigLocationFile_open(&(locations->locations[locations->depth+1].file), path, debug_flag);
    if (r)
    {
        return r; // Failed
    }
    locations->depth++;
    return r;
}

int
ConfigLocations_open_folder(struct ConfigLocations * locations,
                            const char * path, int debug_flag)
{
    int r;
    
    r = ConfigLocations_check_free_slots(locations, path, debug_flag);
    if (r)
    {
        return r;
    }
    r = ConfigLocationFolder_open(&(locations->locations[locations->depth+1].folder), path, debug_flag);
    if (r)
    {
        return r; // Failed
    }

    locations->depth++;
    return r;
}

int
ConfigLocations_open_glob(struct ConfigLocations * locations,
                          const char * pattern, int debug_flag)
{
    int r;

    r = ConfigLocations_check_free_slots(locations, pattern, debug_flag);
    if (r)
    {
        return r;
    }
    r = ConfigLocationGlob_open(&(locations->locations[locations->depth+1].glob), pattern, debug_flag);
    if (r)
    {
        return r; // Failed
    }

    locations->depth++;
    return r;


}

char *
ConfigLocations_fgets(struct ConfigLocations *locations,
                      char * line, size_t line_length,
                      const char ** filepath, int * line_number,
                      int debug_flag)
{
    char * l;
    int r;
    if (locations->depth == -1)
    {
        return NULL; // We have no more files to work with
    }
    while (locations->depth > -1)
    {
        switch (locations->locations[locations->depth].location_type)
        {
            case CONFIGLOCATION_FILE:
                l = ConfigLocationFile_fgets(
                    &(locations->locations[locations->depth].file),
                    line,
                    line_length,
                    filepath,
                    line_number
                );
                if (l)
                {
                    return l;
                }

                if (!ConfigLocationFile_feof(&(locations->locations[locations->depth].file)))
                {
                    // Error reading from file
                    *filepath = locations->locations[locations->depth].file.file_path;
                    *line_number = locations->locations[locations->depth].file.line_number;
                    return NULL;
                }
                
                ConfigLocations_close(locations);
                break;

            case CONFIGLOCATION_FOLDER:
                if (ConfigLocationFolder_nextfilepath(
                    &(locations->locations[locations->depth].folder),
                    &l,
                    debug_flag
                ))
                {
                    // There are no more files to read
                    return NULL;
                }
                
                if (l == NULL)
                {
                    // No more files;
                    ConfigLocations_close(locations);
                    break;
                }
                
                r=ConfigLocations_open_file(locations, l, debug_flag);
                free(l);
                if (r){
                    return NULL;
                }
                if (!ConfigLocationFile_isfile(&(locations->locations[locations->depth].file)))
                {
                    ConfigLocations_close(locations);
                }
                break;
            case CONFIGLOCATION_GLOB:
                if (ConfigLocationGlob_nextfilepath(
                    &(locations->locations[locations->depth].glob),
                    &l,
                    debug_flag
                ))
                {
                    // There are no more files to read
                    return NULL;
                }
                
                if (l == NULL)
                {
                    // No more files;
                    ConfigLocations_close(locations);
                    break;
                }
                
                r=ConfigLocations_open_file(locations, l, debug_flag);
                free(l);
                if (r)
                {
                    return NULL;
                }
                if (!ConfigLocationFile_isfile(&(locations->locations[locations->depth].file)))
                {
                    ConfigLocations_close(locations);
                }
                break;
            default:
                return NULL;
        }
    }
    return NULL;
}