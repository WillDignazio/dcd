#include "dcd.h"

#include <microhttpd.h>

struct MHD_Response*
route_lease(struct Request *request) {
  (void)request;
  printf("LEASE HANDLER\n");
  return NULL;
}
