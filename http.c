#include "dcd.h"

#include <time.h>
#include <glib.h>
#include <microhttpd.h>

struct Route {
  const char *url;
  const char *mime;
};

static GHashTable *route_table;

static int
get_uri_iterator(void *cls,
		 enum MHD_ValueKind kind,
		 const char *key,
		 const char *value) {
  (void)cls;
  (void)kind;
  (void)key;
  (void)value;

  struct Request *request;

  request = (struct Request*)cls;
  if (request == NULL) {
    fprintf(stderr, "Received get_uri_iterator without request object.\n");
    return MHD_NO;
  }

  if (request->params == NULL) {
    fprintf(stderr, "Params store is not initialized for request object.\n");
    return MHD_NO;
  }

  /* Insert this parameter into the request object param store */
  g_hash_table_insert(request->params, (gpointer)key, (gpointer)value);

  return MHD_YES;
}

static int
post_iterator(void *cls,
	      enum MHD_ValueKind kind,
	      const char *key,
	      const char *filename,
	      const char *content_type,
	      const char *transfer_encoding,
	      const char *data, uint64_t off, size_t size) {
  (void)cls;
  (void)kind;
  (void)key;
  (void)filename;
  (void)content_type;
  (void)transfer_encoding;
  (void)data;
  (void)off;
  (void)size;

  printf("TODO: HANDLING POST....\n");

  return MHD_YES;
}

struct Request*
alloc_request(void) {
  struct Request *request;

  request = (struct Request*)calloc(1, sizeof(*request));
  if (request == NULL) {
    fprintf(stderr, "Failed to allocate Request object.\n");
    return NULL;
  }

  request->params = g_hash_table_new(&g_str_hash, &g_str_equal);

  return request;
}

void
free_request(struct Request* request) {
  if (request == NULL) {
    fprintf(stderr, "Attempted to free NULL request object.\n");
    return;
  }

  if (request->params != NULL) {
    g_hash_table_destroy(request->params);
  }

  free(request);
}

void
print_keyval(gpointer key, gpointer value, gpointer user_data) {
  (void)user_data;
  printf("keyval: %s=%s\n", key, value);
}

void
request_completed(void *cls, struct MHD_Connection *connection,
		  void **con_cls,
		  enum MHD_RequestTerminationCode toe)
{
  (void)cls;
  (void)connection;
  (void)toe;

  struct Request *request;

  request = *con_cls;
  if (request == NULL) {
    fprintf(stderr, "Failed to receive Request object on request_completed.\n");
    return;
  }

  g_hash_table_foreach(request->params, &print_keyval, NULL);
  
  free_request(request);
  *con_cls = NULL;
}

int answer_to_connection (void *cls, struct MHD_Connection *connection,
			  const char *url,
			  const char *method, const char *version,
			  const char *upload_data,
			  size_t *upload_data_size, void **con_cls)
{
  (void)cls;
  (void)url;
  (void)version;

  struct Request *request;
  struct MHD_Response *response;
  int ret;
  
  request = NULL;
  response = NULL;
  ret = -1;

  request = (struct Request*)*con_cls;
  if (request == NULL) {

    request = alloc_request();
    if (request == NULL) {
      fprintf(stderr, "Failed to allocate request struct.\n");
      return MHD_NO;
    }

    *con_cls = request;
    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
      request->post = MHD_create_post_processor(connection,
						HTTP_PROCESS_BUFFER_SIZE,
						&post_iterator, request);
      if (request->post == NULL) {
	fprintf(stderr, "Failed to setup post processor for %s\n", url);
	return MHD_NO;
      }
    }

    return MHD_YES;
  }

  if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
    /* Consume, handle POST data */
    MHD_post_process(request->post, upload_data, *upload_data_size);
    if (*upload_data_size != 0) {
      *upload_data_size = 0;
      return MHD_YES;
    }

    /* Done with POST data, send response */
    MHD_destroy_post_processor(request->post);
    request->post = NULL;

    /* XXX TODO: SERVE PROPER POST RESPONSE */
    response = MHD_create_response_from_buffer(strlen(bad_request_page),
					       (void*)bad_request_page,
					       MHD_RESPMEM_PERSISTENT);
  } else if (strcmp(method, MHD_HTTP_METHOD_GET) == 0) {
    /* Get the URL key=val arguments */
    MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, get_uri_iterator, request);

    RouteHandler handler;

    handler = g_hash_table_lookup(route_table, url);
    if (handler == NULL) {
      response = NULL;
      goto respond;
    }

    response = handler(request);
  }

 respond:
  if (response == NULL) {
    return MHD_NO;
  }
  
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

  MHD_destroy_response(response);
  return ret;
}

struct MHD_Daemon*
http_init(int port)
{
  struct MHD_Daemon *daemon = NULL;

  daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
			    &answer_to_connection, NULL,
			    MHD_OPTION_NOTIFY_COMPLETED, &request_completed, NULL,
			    MHD_OPTION_END);
  if (daemon == NULL) {
    fprintf(stderr, "Failed to allocate MHD daemon\n");
    goto fail;
  }

  route_table = g_hash_table_new(&g_str_hash, &g_str_equal);
  if (route_table == NULL) {
    fprintf(stderr, "Failed to initialize route table.");
    goto fail;
  }

  /* Configure routes */
  g_hash_table_insert(route_table, "/lease", &route_lease);

  return daemon;

 fail:
  http_shutdown(daemon);
  return NULL;
}

void
http_shutdown(struct MHD_Daemon *daemon)
{
  if (daemon != NULL)
    MHD_stop_daemon(daemon);
  if (route_table != NULL)
    g_hash_table_destroy(route_table);
}
