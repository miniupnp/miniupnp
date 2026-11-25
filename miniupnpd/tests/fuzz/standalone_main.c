/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * MiniUPnP project
 * http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * This software is subject to the conditions detailed
 * in the LICENCE file provided within the distribution */

/* Minimal driver to run a fuzz target on files without libFuzzer,
 * e.g. to reproduce a crash: ./fuzz_http_repro crash-file ... */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerInitialize(int * argc, char * * * argv);
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size);

int main(int argc, char * * argv)
{
	int i;
	LLVMFuzzerInitialize(&argc, &argv);
	for(i = 1; i < argc; i++) {
		FILE * f = fopen(argv[i], "rb");
		uint8_t * buf;
		long n;
		if(f == NULL) {
			perror(argv[i]);
			return 1;
		}
		fseek(f, 0, SEEK_END);
		n = ftell(f);
		fseek(f, 0, SEEK_SET);
		buf = malloc(n > 0 ? n : 1);
		if(buf == NULL || (n > 0 && fread(buf, 1, n, f) != (size_t)n)) {
			fclose(f);
			free(buf);
			return 1;
		}
		fclose(f);
		LLVMFuzzerTestOneInput(buf, (size_t)n);
		free(buf);
		printf("%s: OK\n", argv[i]);
	}
	return 0;
}
