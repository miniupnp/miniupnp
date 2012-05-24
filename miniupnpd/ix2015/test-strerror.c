#include <stdlib.h>
#include <string.h>

main()
{
  int i;
  char buf[128];

  for(i = 0; i < 256; i++)
    {
      strerror_r(i, buf, 128);
      printf("%3d: %s\n", i, buf);
      strerror_r(0, buf, 128);
      printf("%3d: %s\n", 0, buf);
    }
  exit(EXIT_SUCCESS);
}
