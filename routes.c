#include "dcd.h"

#include <glib.h>
#include <microhttpd.h>

struct MHD_Response*
route_lease(struct Request *request)
{
  (void)request;

  json_t *json;

  char *address = g_hash_table_lookup(request->params, DCD_PARAM_ADDR);
  if (address == NULL) {
    return MHD_create_response_from_buffer(strlen(bad_request_page),
					   (void*)bad_request_page,
					   MHD_RESPMEM_PERSISTENT);
  }

  json = dcd_get_lease(address, global_ctx);
  if (json == NULL) {
    return NULL;
  }

  char *response = json_dumps(json, 0);
  if (response == NULL) {
    fprintf(stderr, "Failed to allocate response.\n");
    goto fail;
  }

  json_decref(json);
  return MHD_create_response_from_buffer(strlen(response),
					 (void*)response,
					 MHD_RESPMEM_MUST_FREE);
 fail:
  if (json != NULL)
    json_decref(json);
  if (response != NULL)
    free(response);

  return NULL;
}
