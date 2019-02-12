#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "minissdpc-libuv.h"
#include <uv.h>

void requestFinish2(void* session, void* userdata, struct UPNPDev* upnpdev)
{
  struct UPNPDev* it;
  (void)userdata;

  for(it = upnpdev; it != NULL; it = it->pNext) {
    printf("url = %s\n", it->descURL);
    printf("st = %s\n", it->st);
    printf("usn = %s\n", it->usn);
    printf("\n");
  }
  disconnectFromMiniSSDPD((uv_stream_t*)session);
}

void requestFinish(void* session, int success, void* userdata)
{
  (void)userdata;
  if (success == 0)
  {
    printf("Error while requesting results.\n");
    return;
  }
  receiveDevicesFromMiniSSDPD(session, &requestFinish2, NULL);
}

void connect_cb(void* session, void* userdata)
{
  if (session == 0) {
    printf("Error while connecting\n");
    return;
  }

  char* search = userdata;

  int ret;
  if ((ret = requestDevicesFromMiniSSDPD(session, search, &requestFinish, NULL)) != MINISSDPC_SUCCESS) {
    printf("Error while requesting devices\n");
    if (ret == MINISSDPC_INVALID_INPUT)
      printf("Invalid input!!\n");
    else if (ret == MINISSDPC_MEMORY_ERROR)
      printf("Can't malloc?\n");
  }
}

int main(int argc, char *argv[])
{
  char* pipeName;
  char* search;

  if (argc < 3) {
    printf("Usage: %s </path/to/minissdpd.socket> <device>\n", argv[0]);
    printf("       ssdp:all for all devices\n");
    return 1;
  }
  pipeName = argv[1];
  search = argv[2];
  connectToMiniSSDPD(pipeName, &connect_cb, search);
  uv_run(uv_default_loop(), UV_RUN_DEFAULT);
  return 0;
}
