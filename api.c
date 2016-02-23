#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>

#include <dhcpctl/dhcpctl.h>
#include <isc-dhcp/result.h>
#include <microhttpd.h>

#include "dcd.h"

dhcpctl_handle
build_connection(struct dcd_ctx *ctx)
{
  dhcpctl_handle connection;
  dhcpctl_status status;

  connection = NULL;
  status = -1;

  status = dhcpctl_connect(&connection, ctx->omapi_address, ctx->omapi_port, ctx->ctl_auth);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to connect to dhcp omapi: %s\n",
	    isc_result_totext(status));
    goto fail;
  }

  return connection;

 fail:
  if (connection != NULL) {
    omapi_object_dereference(&connection, MDL);
  }
  return NULL;
}

int
determine_family(const char *address)
{
  struct addrinfo hint;
  struct addrinfo *res;
  int type;
  int ret;

  if (address == NULL) {
    return -1;
  }

  memset(&hint, '\0', sizeof(hint));
  hint.ai_family = PF_UNSPEC;
  hint.ai_flags = AI_NUMERICHOST;
  
  ret = getaddrinfo(address, NULL, &hint, &res);
  if (ret) {
    fprintf(stderr, "Invalid address\n");
    return -1;
  }

  if (res->ai_family == AF_INET) {
    type = AF_INET;
  } else if (res->ai_family == AF_INET6) {
    type = AF_INET6;
  } else {
    type = -1;
  }

  freeaddrinfo(res);
  return type;
}

dhcpctl_status
open_object_sync(dhcpctl_handle handle, dhcpctl_handle connection)
{
  dhcpctl_status status;
  dhcpctl_status waitstatus;

  status = -1;
  waitstatus = -1;

  status = dhcpctl_open_object(handle, connection, 0);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to open object: %s\n",
	    isc_result_totext(status));
    goto done;
  }

  status = dhcpctl_wait_for_completion(handle, &waitstatus);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to initialize wait: %s\n",
	    isc_result_totext(status));
    goto done;
  }
  if (waitstatus != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to wait for completion of handle wait: %s\n",
	    isc_result_totext(waitstatus));
    status = waitstatus;
    goto done;
  }

 done:
  return status;
}

json_t*
dcd_get_lease(const char *address, struct dcd_ctx *ctx)
{
  dhcpctl_handle lease;
  dhcpctl_handle connection;
  dhcpctl_status status;
  dhcpctl_status waitstatus;
  dhcpctl_data_string ipaddrstr;
  dhcpctl_data_string val_lease_ends;
  struct in_addr convaddr;
  char *result;
  int ret;
  int type;

  ret = -1;
  type = -1;
  val_lease_ends = NULL;
  lease = dhcpctl_null_handle;
  result = NULL;
  ipaddrstr = NULL;
  status = -1;
  waitstatus = -1;

  sem_wait(&ctx->sem_lock);

  connection = build_connection(ctx);
  if (connection == NULL) {
    goto done;
  }

  memset(&lease, 0, sizeof(lease));
  status = dhcpctl_new_object(&lease, connection, DHCP_PARAM_LEASE);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to retrieve lease object.\n");
    goto done;
  }

  type = determine_family(address);
  if (type == -1) {
    goto done;
  }

  memset (&ipaddrstr, 0, sizeof(ipaddrstr));

  ret = inet_pton(type, address, &convaddr);
  if (ret != 1) {
    fprintf(stderr, "Failed to get inet_pton: %s\n", strerror(errno));
    goto done;
  }

  status = omapi_data_string_new (&ipaddrstr, 4, MDL);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to allocate ipaddrstr for lease: %s\n",
	    isc_result_totext(status));
    goto done;
  }

  memcpy(ipaddrstr->value, &convaddr.s_addr, 4);

  status = dhcpctl_set_value(lease, ipaddrstr, DHCP_PARAM_IPADDRESS);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to set DHCP_PARAM_IPADDRESS from lease object: %s\n",
	    isc_result_totext(status));
    goto done;
  }

  status = open_object_sync(lease, connection);
  if (status != ISC_R_SUCCESS) {
    goto done;
  }

  status = dhcpctl_get_value(&val_lease_ends, lease, DHCP_PARAM_ENDS);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to get DHCP_PARAM_ENDS value: %s\n",
	    isc_result_totext(status));
    goto done;
  }

  time_t thetime = 0;
  memcpy(&thetime, val_lease_ends->value, val_lease_ends->len);

  thetime = htonl(thetime);
  fprintf(stdout, "Ending Time: %s\n", ctime(&thetime));
  
 done:
  if (ipaddrstr != NULL)
    dhcpctl_data_string_dereference(&ipaddrstr, MDL);
  if (val_lease_ends != NULL)
    dhcpctl_data_string_dereference(&val_lease_ends, MDL);
  if (connection != NULL)
    omapi_object_dereference(&connection, MDL);
  if (lease != NULL)
    omapi_object_dereference(&lease, MDL);

  sem_post(&ctx->sem_lock);
  return NULL;
}

int
check_connection(struct dcd_ctx *ctx)
{
  dhcpctl_status status;
  dhcpctl_status waitstatus;
  dhcpctl_handle connection;
  dhcpctl_handle interface_handle;
  struct ifaddrs *ifaddr, *ifa;
  dhcpctl_status ret;
  
  status = -1;
  waitstatus = -1;
  interface_handle = dhcpctl_null_handle;
  ifaddr = NULL;
  ifa = NULL;
  ret = -1;

  connection = build_connection(ctx);
  if (connection == NULL) {
    goto fail;
  }
  
  status = dhcpctl_new_object(&interface_handle, connection, DHCP_PARAM_INTERFACE);
  if (status != ISC_R_SUCCESS) {
    fprintf(stderr, "Failed to allocate connection test interface: %s\n",
	    isc_result_totext(status));
    ret = status;
    goto fail;
  }

  if (getifaddrs(&ifaddr) == -1) {
    fprintf(stderr, "Failed to get list of interfaces for checking connection: %s\n",
	    strerror(errno));
    goto fail;
  }
  
  /* Test for each interface */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL || ifa->ifa_name == NULL) {
      continue;
    }
    
    status = dhcpctl_set_string_value(interface_handle, ifa->ifa_name, DHCP_PARAM_NAME);
    if (status != ISC_R_SUCCESS) {
      ret = status;
      continue;
    }
    status = dhcpctl_open_object(interface_handle, connection, 0);
    if (status != ISC_R_SUCCESS) {
      ret = status;
      continue;
    }

    status = dhcpctl_wait_for_completion(interface_handle, &waitstatus);
    if (status != ISC_R_SUCCESS) {
      ret = status;
      continue;
    }

    if (waitstatus != ISC_R_SUCCESS) {
      ret = waitstatus;
      continue;
    }

    printf("Found valid interface for connection: %s\n", ifa->ifa_name);
    ret = status;
    break;
  }

 fail:
  if (ifaddr != NULL)
    freeifaddrs(ifaddr);

  if (connection != NULL)
    omapi_object_dereference(&connection, MDL);

  if (interface_handle != NULL)
    omapi_object_dereference(&interface_handle, MDL);
  
  return ret;
}

struct dcd_ctx*
dcd_init(const char *address, int port,
	 const char *secret_keyname,
	 const char *secret_algo,
	 const unsigned char *secret,
	 int http_port)
{

  struct MHD_Daemon *daemon;
  struct dcd_ctx *ctx;
  dhcpctl_status status;

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

  if (secret_keyname == NULL) {
    printf("secret_keyname is null\n");
  }
  if (secret == NULL) {
    printf("secret is null\n");
  }
  
  if (secret_keyname || secret) {
    if ((secret_keyname == NULL && secret != NULL) ||
	(secret_keyname != NULL && secret == NULL)) {
      fprintf(stderr, "Invalid argument: missing secret_keyname, secret_algo, or secret\n");
      goto fail;
    }
    
    printf("Configuring authenticator...\n");
    status = dhcpctl_new_authenticator(&ctx->ctl_auth,
				       secret_keyname,
				       secret_algo, secret,
				       strnlen((const char *)secret, OMAPI_MAX_SECRET_LEN) + 1);
    if (status != ISC_R_SUCCESS) {
      fprintf(stderr, "Failed to create authenticator object: %s\n",
	      isc_result_totext(status));
      goto fail;
    }
  } else {
    ctx->ctl_auth = NULL;
  }

  /* Required to establish a connection */
  ctx->omapi_address = address;
  ctx->omapi_port = port;

  status = check_connection(ctx);
  if (status != ISC_R_SUCCESS) {
    goto fail;
  }

  daemon = http_init(http_port);
  if (daemon == NULL) {
    goto fail;
  }

  ctx->mhd_daemon = daemon;
  
  /* TODO: pass in max conn count */
  if (sem_init(&ctx->sem_lock, 0, DCD_MAX_CONN) != 0) {
    goto fail;
  }

  return ctx;

 fail:
  if (ctx != NULL) {
    if (ctx->mhd_daemon != NULL) {
      MHD_stop_daemon(ctx->mhd_daemon);
    }

    free(ctx);
  }

  return NULL;
}

void
dcd_shutdown(struct dcd_ctx *ctx)
{
  sem_destroy(&ctx->sem_lock);
  if (ctx->mhd_daemon != NULL)
    MHD_stop_daemon(ctx->mhd_daemon);
  if (ctx->ctl_auth != NULL)
    omapi_object_dereference(&ctx->ctl_auth, MDL);
}
