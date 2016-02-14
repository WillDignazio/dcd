#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include <dhcpctl/dhcpctl.h>
#include <isc-dhcp/result.h>
#include <microhttpd.h>

#include "dcd.h"

struct dcd_ctx*
dcd_init(char *address, int port,
	 char *secret_keyname,
	 char *secret_algo,
	 char *secret,
	 int http_port) {

  struct MHD_Daemon *daemon;
  struct dcd_ctx *ctx;
  dhcpctl_status result;

  /*
   * OMAPI doesn't properly handle uninitiailized handles/ctx's.
   * If we don't zero-out the various handles, it throws "invalid argument"
   */
  ctx = (struct dcd_ctx*)calloc(1, sizeof(struct dcd_ctx));
  if (ctx == NULL) {
    fprintf(stderr, "Failed to allocate dcd_ctx: %s\n", strerror(errno));
    goto fail;
  }

  dhcpctl_initialize();
  
  if (secret_keyname || secret) {
    if ((secret_keyname == NULL && secret != NULL) ||
	(secret_keyname != NULL && secret == NULL)) {
      fprintf(stderr, "Invalid argument: missing secret_keyname, secret_algo, or secret\n");
      goto fail;
    }
    
    result = dhcpctl_new_authenticator(&ctx->ctl_auth,
				       secret_keyname,
				       secret_algo, secret,
				       strlen(secret) + 1);
    if (result != ISC_R_SUCCESS) {
      fprintf(stderr, "Failed to create authenticator object: %s\n",
	      isc_result_totext(result));
      goto fail;
    }

  } else {
    ctx->ctl_auth = NULL;
  }

  result = dhcpctl_connect(&ctx->ctl_handle, address, port, ctx->ctl_auth);
  if (result != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to connect to dhcp omapi: %s\n",
	    isc_result_totext(result));
    goto fail;
  }
  
  daemon = http_init(http_port);
  if (daemon == NULL) {
    goto fail;
  }

  ctx->omapi_address = address;
  ctx->omapi_port = port;
  ctx->mhd_daemon = daemon;

  return ctx;

 fail:
  if (ctx != NULL) {
    free(ctx);
  }
}
