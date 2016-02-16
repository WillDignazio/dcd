#ifndef __DCD__
#define __DCD__

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include <dhcpctl/dhcpctl.h>

#define OMAPI_MAX_SECRET_LEN 200
#define OMAPI_DEFAULT_PORT 7911
#define OMAPI_DEFAULT_ADDR "127.0.0.1"
#define OMAPI_DEFAULT_SECRET_ALGO "hmac-md5"

#define HTTP_PROCESS_BUFFER_SIZE 65536
#define HTTP_DEFAULT_PORT 8080

struct dcd_ctx {
  dhcpctl_handle ctl_handle;
  dhcpctl_handle ctl_auth;
  struct MHD_Daemon *mhd_daemon;
  const char *omapi_address;
  int omapi_port;
};

/**
 * Initialize a new dcd context, this creates the necessary underlying
 * contexts and connections. This includes, but is not limited to, the
 * underlying dhcpctl connection, and httpd library initialization.
 * 
 * If an error occurs, the return pointer shall be NULL, otherwise the
 * returned pointer will contain a valid initialized dcd_ctx struct.
 */
struct dcd_ctx* dcd_init(const char *address, int port,
			 const char *secret_keyname,
			 const char *secret_algo,
			 const unsigned char *secret,
			 int http_port);


/* http.c */
struct Request;
struct MHD_Daemon* http_init(int port);


/* routes.c */
typedef struct MHD_Response* (*RouteHandler)(struct Request *request);
struct MHD_Response* route_lease(struct Request *request);

#endif
