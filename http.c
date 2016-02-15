#include "dcd.h"

#include <time.h>
#include <uuid/uuid.h>
#include <glib.h>
#include <microhttpd.h>

#define COOKIE_NAME "mhd_dcd_session"

static const char *bad_request_page = "<html><p><b>400 Bad Request</b></p></html>";
static GHashTable *sessions_table = NULL;

struct Session {
  struct Session *next;	// Next session (kept in linked list)
  uuid_t uuid;		// Unique ID
  time_t start;		// Time when this session was last active

  char value_1[64];	// TEST: String submitted via form
  char value_2[64];	// TEST: Another string submitted via form
};

struct Request {
  struct Session *session;		// Associated Session
  struct MHD_PostProcessor *post;	// Post processing of handling form data (eg. POST Request)
  const char *post_url;			// URL to serve in response to (possible) POST request
};

/* static void */
/* add_session_cookie(struct Session *session, */
/* 		   struct MHD_Response *response) { */
/*   char str[256]; */
/*   char uuid_str[37]; */

/*   uuid_unparse(session->uuid, uuid_str); */
/*   snprintf(str, sizeof(str), "%s=%s", COOKIE_NAME, uuid_str); */

/*   if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, str) == MHD_NO) { */
/*     fprintf(stderr, "Failed to set session cookie header!\n"); */
/*   } */
/* } */

struct Session*
get_session(struct MHD_Connection *connection) {
  gpointer cookie;
  struct Session *session;
  
  cookie = (gpointer)MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, "session");
  if (cookie != NULL) {
    /* We have an active session for this user, and need to service it */
    gpointer *session_ptr;
    
    session_ptr = g_hash_table_lookup(sessions_table, cookie);
    if (session_ptr == NULL) {
      fprintf(stderr, "Unable to find session, even though we should have it.\n");
      return MHD_NO;
    }
   
    printf("Got session object: %s\n", (char*)cookie);
    session = (struct Session*)session_ptr;
  } else {
    session = calloc(1, sizeof(struct Session));
    if (session == NULL) {
      fprintf(stderr, "Unable to allocate session object\n");
      return MHD_NO;
    }

    uuid_generate(session->uuid);
    session->start = time(NULL); 

    /* TODO: Cleanup, a little roundabout */
    char uuid_str[37];
    uuid_unparse(session->uuid, uuid_str);
    g_hash_table_insert(sessions_table, uuid_str, &session);

    printf("Inserted session object: %s\n", (char*)uuid_str);
  }

  return session;
}

static int
post_iterator(void *cls,
	      enum MHD_ValueKind kind,
	      const char *key,
	      const char *filename,
	      const char *content_type,
	      const char *transfer_encoding,
	      const char *data, uint64_t off, size_t size) {

  (void)kind;
  (void)key;
  (void)filename;
  (void)content_type;
  (void)transfer_encoding;
  (void)data;
  (void)off;
  (void)size;

  struct Request *request = cls;
  struct Session *session = request->session;

  char uuid_str[37];
  uuid_unparse(session->uuid, uuid_str);
  fprintf(stdout, "ITERATOR for session: %s\n", uuid_str);
  return MHD_YES;
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
  (void)upload_data;
  (void)upload_data_size;
  (void)con_cls;

  struct Request *request;
  struct Session *session;
  struct MHD_Response *response;
  int ret;
  
  request = NULL;
  session = NULL;
  response = NULL;
  ret = -1;

  request = (struct Request*)con_cls;
  if (request == NULL) {
    printf("Created request object for connection\n");

    request = (struct Request*)calloc(1, sizeof(struct Request));
    if (request == NULL) {
      fprintf(stderr, "Failed to allocate request struct.\n");
      return MHD_NO;
    }

    *con_cls = request;
    if (strcmp(method, MHD_HTTP_METHOD_POST)) {
      printf("Servicing POST request.\n");
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

  if (request->session == NULL) {
    request->session = get_session(connection);
    if (session == NULL) {
      fprintf(stderr, "Failed to establish connection session.\n");
      return MHD_NO;
    }
  }

  session = request->session;
  session->start = time(NULL);

  if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
    /* Consume, handle POST data */
    MHD_post_process(request->post,
		     upload_data,
		     *upload_data_size);
    if (*upload_data_size != 0) {
      *upload_data_size = 0;
      return MHD_YES;
    }

    /* Done with POST data, send response */
    MHD_destroy_post_processor(request->post);
    request->post = NULL;

    method = MHD_HTTP_METHOD_GET; // faked to carry on
    if (request->post_url != NULL) {
      url = request->post_url;
    }
  }

  response = MHD_create_response_from_buffer(strlen(bad_request_page),
					     (void*)bad_request_page,
					     MHD_RESPMEM_PERSISTENT);

  if (response == NULL) {
    return MHD_NO;
  }
  
  ret = MHD_queue_response(connection,
			   MHD_HTTP_OK,
			   response);

  MHD_destroy_response(response);

  return ret;
}

struct MHD_Daemon*
http_init(int port) {
  struct MHD_Daemon *daemon = NULL;

  sessions_table = g_hash_table_new(&g_str_hash,
				    &g_str_equal);
  if (sessions_table == NULL) {
    fprintf(stderr, "Failed to initialize http sessions table\n");
    goto fail;
  }
  
  daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
			    &answer_to_connection, NULL, MHD_OPTION_END);
  if (daemon == NULL) {
    fprintf(stderr, "Failed to allocate MHD daemon\n");
    goto fail;
  }

  return daemon;

 fail:
  if (daemon != NULL) {
    MHD_stop_daemon(daemon);
  }

  if (sessions_table != NULL) {
    g_hash_table_destroy(sessions_table);
  }

  return NULL;
}

