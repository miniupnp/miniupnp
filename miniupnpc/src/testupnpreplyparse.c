/* $Id: testupnpreplyparse.c,v 1.4 2014/01/27 11:45:19 nanard Exp $ */
/* MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * (c) 2006-2026 Thomas Bernard
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "upnpreplyparse.h"

int
test_parsing(const char * buf, int len, FILE * f)
{
	char line[1024];
	struct NameValueParserData pdata;
	int ok = 1;
	ParseNameValue(buf, len, &pdata);
	/* check result */
	if(f != NULL)
	{
		while(fgets(line, sizeof(line), f))
		{
			char * value;
			char * equal;
			char * parsedvalue;
			int l;
			l = strlen(line);
			while((l > 0) && ((line[l-1] == '\r') || (line[l-1] == '\n')))
				line[--l] = '\0';
			/* skip empty lines */
			if(l == 0)
				continue;
			equal = strchr(line, '=');
			if(equal == NULL)
			{
				fprintf(stderr, "Warning, line does not contain '=' : %s\n", line);
				continue;
			}
			*equal = '\0';
			value = equal + 1;
			parsedvalue = GetValueFromNameValueList(&pdata, line);
			if((parsedvalue == NULL) || (strcmp(parsedvalue, value) != 0))
			{
				fprintf(stderr, "Element <%s> : expecting value '%s', got '%s'\n",
				        line, value, parsedvalue ? parsedvalue : "<null string>");
				ok = 0;
			}
		}
	}
	ClearNameValueList(&pdata);
	return ok;
}

int main(int argc, char * * argv)
{
	FILE * f = NULL;
	char * buffer;
	long l;
	int i;
	int ok;
	int add_null_terminator = 0;
	const char * name_value_file = NULL;

	if(argc<2 || 0 == strcmp("--help", argv[1]) || 0 == strcmp("-h", argv[1])) {
		fprintf(stderr, "Usage: %s [--nullterminate] file.xml [file.namevalues]\n", argv[0]);
		return 1;
	}
	for(i = 1; i < argc; i++) {
		if(0 == strcmp(argv[i], "--nullterminate")) {
			add_null_terminator = 1;
		} else if(f == NULL) {
			f = fopen(argv[i], "r");
			if(!f)
			{
				fprintf(stderr, "Error : can not open file %s\n", argv[1]);
				return 2;
			}
		} else if(name_value_file == NULL) {
			name_value_file = argv[i];
		} else {
			fprintf(stderr, "unrecognized argument %s\n", argv[i]);
			return 1;
		}
	}
	if(fseek(f, 0, SEEK_END) < 0) {
		perror("fseek");
		return 1;
	}
	l = (int)ftell(f);
	if(l < 0) {
		perror("ftell");
		return 1;
	}
	if(fseek(f, 0, SEEK_SET) < 0) {
		perror("fseek");
		return 1;
	}
	buffer = malloc(l + (add_null_terminator ? 1 : 0));
	if(buffer == NULL) {
		fprintf(stderr, "Error: failed to allocate %ld bytes\n", l+1);
		return 1;
	}
	l = fread(buffer, 1, l, f);
	fclose(f);
	f = NULL;
	if(add_null_terminator) {
		buffer[l] = '\0';
	}
	if(name_value_file)
	{
		f = fopen(name_value_file, "r");
		if(!f)
		{
			fprintf(stderr, "Error : can not open file %s\n", name_value_file);
			return 2;
		}
	}
#ifdef DEBUG
	DisplayNameValueList(buffer, l);
#endif
	ok = test_parsing(buffer, l, f);
	if(f)
	{
		fclose(f);
	}
	free(buffer);
	return ok ? 0 : 3;
}

