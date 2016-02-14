#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include <argp.h>
#include <dhcpctl/dhcpctl.h>
#include <isc-dhcp/result.h>

#include "dcd.h"

const char *argp_program_version = "dcd v0.1";
const char *argp_program_bug_address = "<slackwill@csh.rit.edu>";

static char doc[] = "dcd -- Dhcp Control Daemon -- network controlled daemon for DHCP";
static char args_doc[] = "<TODO>";

static struct argp_option options[] = {
  {"verbose",  		'v',	0,      0,	"Produce verbose output" },
  {"omapi-port",	'p',	"PORT",	   0,	"OMAPI connection port"	},
  {"omapi-addr",	'a',	"ADDRESS", 0,	"OMAPI connection address" },
  {"omapi-key-name",	'k',	"KEYNAME", 0,	"OMAPI connection secret key name" },
  {"omapi-algo",	'e',	"ALGO", 0,	"OMAPI connection secret algo" },
  {"omapi-secret",	's',	"SECRET", 0,	"OMAPI connection secret"} ,
  { 0 }
};

struct arguments
{
  char *omapi_address;
  char *omapi_secret;
  char *omapi_secret_keyname;
  char *omapi_secret_algo;
  int omapi_port;
  int verbose;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = 1;
      break;
    case 'p':
      arguments->omapi_port = strtonum(arg, 1, 65535, "Invalid port number, must be [0,65535]");
      break;
    case 'a':
      arguments->omapi_address = arg;
      break;
    case 'k':
      arguments->omapi_secret_keyname = arg;
      break;
    case 's':
      arguments->omapi_secret = arg;
      break;
    case 'e':
      arguments->omapi_secret_algo = arg;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

struct dcd_ctx*
dcd_init(char *address, int port,
	 char *secret_keyname,
	 char *secret_algo,
	 char *secret) {

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
  
  ctx->omapi_address = address;
  ctx->omapi_port = port;

  return ctx;

 fail:
  if (ctx != NULL) {
    free(ctx);
  }
}

int main(int argc, char *argv[]) {
  struct arguments arguments;
  
  arguments.verbose = 0;
  arguments.omapi_port = OMAPI_DEFAULT_PORT;
  arguments.omapi_secret = NULL;
  arguments.omapi_secret_keyname = NULL;
  arguments.omapi_secret_algo = OMAPI_DEFAULT_SECRET_ALGO;
  arguments.omapi_address = OMAPI_DEFAULT_ADDR;

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  dcd_init(arguments.omapi_address, arguments.omapi_port,
	   arguments.omapi_secret_keyname,
	   arguments.omapi_secret_algo,
	   arguments.omapi_secret);
  
  return 0;
}
