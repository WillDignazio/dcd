#ifndef __DCD__
#define __DCD__

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

#include <glib.h>
#include <jansson.h>
#include <dhcpctl/dhcpctl.h>

#define OMAPI_MAX_SECRET_LEN 200
#define OMAPI_DEFAULT_PORT 7911
#define OMAPI_DEFAULT_ADDR "127.0.0.1"
#define OMAPI_DEFAULT_SECRET_ALGO "HMAC-MD5"

#define HTTP_PROCESS_BUFFER_SIZE 65536
#define HTTP_DEFAULT_PORT 8080

extern struct dcd_ctx *global_ctx;

#define DCD_MAX_CONN 10 
#define DCD_PARAM_ADDR "address"

struct dcd_ctx {
  sem_t sem_lock;
  dhcpctl_handle ctl_auth;
  struct MHD_Daemon *mhd_daemon;
  const char *omapi_address;
  int omapi_port;
};

/* api.c */
#define DHCP_PARAM_IPADDRESS "ip-address"
#define DHCP_PARAM_LEASE "lease"
#define DHCP_PARAM_ENDS "ends"
#define DHCP_PARAM_INTERFACE "interface"
#define DHCP_PARAM_NAME "name"

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

json_t* dcd_get_lease(const char *address, struct dcd_ctx *ctx);
void dcd_shutdown(struct dcd_ctx *ctx);

/* http.c */
static const char *bad_request_page = "<html><p><b>400 Bad Request</b></p></html>";

struct Request;
struct MHD_Daemon* http_init(int port);
void http_shutdown(struct MHD_Daemon *daemon);

struct Request {
  struct MHD_PostProcessor *post;	// POST processing of handling form data (eg. POST Request)
  const char *post_url;			// URL to serve in response to (possible) POST request
  GHashTable *params;			// GET request parameters
};

/* routes.c */
typedef struct MHD_Response* (*RouteHandler)(struct Request *request);
struct MHD_Response* route_lease(struct Request *request);

#endif
