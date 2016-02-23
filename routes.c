#include "dcd.h"

#include <glib.h>
#include <microhttpd.h>

struct MHD_Response*
route_lease(struct Request *request)
{
  (void)request;

  dhcpctl_data_string ipaddrstr;

  char *address = g_hash_table_lookup(request->params, DCD_PARAM_ADDR);
  if (address == NULL) {
    return MHD_create_response_from_buffer(strlen(bad_request_page),
					   (void*)bad_request_page,
					   MHD_RESPMEM_PERSISTENT);
  }

  ipaddrstr = dcd_get_lease(address, global_ctx);
  if (ipaddrstr == NULL) {
    return NULL;
  }

  char *response = malloc(sizeof(ipaddrstr));
  memcpy(response, ipaddrstr->value, ipaddrstr->len);

  dhcpctl_data_string_dereference(&ipaddrstr, MDL);
  return MHD_create_response_from_buffer(strlen(response),
					 (void*)response,
					 MHD_RESPMEM_MUST_FREE);
}
