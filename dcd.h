#ifndef __DCD__
#define __DCD__

#include <dhcpctl/dhcpctl.h>

#define OMAPI_DEFAULT_PORT 7911
#define OMAPI_DEFAULT_ADDR "127.0.0.1"

struct dcd_ctx {
  dhcpctl_handle ctl_handle;
  dhcpctl_handle ctl_auth;
  char *omapi_address;
  int omapi_port;
};

#endif
