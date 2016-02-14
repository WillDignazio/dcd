#include "dcd.h"

#include <microhttpd.h>

int answer_to_connection (void *cls, struct MHD_Connection *connection,
			  const char *url,
			  const char *method, const char *version,
			  const char *upload_data,
			  size_t *upload_data_size, void **con_cls)
{
  const char *page = "<html><body>Hello, browser!</body></html>";
  struct MHD_Response *response;
  int ret;
  
  response = MHD_create_response_from_buffer(strlen(page),
					     (void*)page, MHD_RESPMEM_PERSISTENT);

  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);

  return ret;
}

struct MHD_Daemon*
http_init(int port) {
  struct MHD_Daemon *daemon;
  
  daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
			    &answer_to_connection, NULL, MHD_OPTION_END);
  if (daemon == NULL) {
    fprintf(stderr, "Failed to allocate MHD daemon: %s\n", strerror);
    goto fail;
  }

  return daemon;

 fail:
  if (daemon != NULL) {
    MHD_stop_daemon(daemon);
  }

  return NULL;
}

