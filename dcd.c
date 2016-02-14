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
  { 0 }
};

struct arguments
{
  int verbose;
  char *omapi_address;
  int omapi_port;
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

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };



struct dcd_ctx*
dcd_init(char *address, int port) {

  struct dcd_ctx *ctx;
  dhcpctl_status result;

  ctx = (struct dcd_ctx*)malloc(sizeof(struct dcd_ctx));
  if (ctx == NULL) {
    fprintf(stderr, "Failed to allocate dcd_ctx: %s\n", strerror(errno));
    return NULL;
  }

  dhcpctl_initialize();

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
  arguments.omapi_address = OMAPI_DEFAULT_ADDR;

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  dcd_init(arguments.omapi_address, arguments.omapi_port);
  
  return 0;
}
