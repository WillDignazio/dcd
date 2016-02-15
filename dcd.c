#include <unistd.h>
#include <bsd/stdlib.h>
#include <argp.h>

#include "dcd.h"

const char *argp_program_version = "dcd v0.1";
const char *argp_program_bug_address = "<slackwill@csh.rit.edu>";

static char doc[] = "dcd -- Dhcp Control Daemon -- network controlled daemon for DHCP";
static char args_doc[] = "<TODO>";

static struct argp_option options[] = {
  {"verbose",  		'v',	NULL,      0,	"Produce verbose output",	0 },
  {"omapi-port",	'p',	"PORT",	   0,	"OMAPI connection port",	0 },
  {"omapi-addr",	'a',	"ADDRESS", 0,	"OMAPI connection address",	0 },
  {"omapi-key-name",	'k',	"KEYNAME", 0,	"OMAPI connection secret key name", 0 },
  {"omapi-algo",	'e',	"ALGO", 0,	"OMAPI connection secret algo", 0 },
  {"omapi-secret",	's',	"SECRET", 0,	"OMAPI connection secret",	0 } ,
  {"http-port",		't',	"PORT",	0,	"HTTP connection port",		0 },
  {"foreground",	'f',	NULL,	0,	"Foreground the daemon",	0 },
  { NULL, 0, NULL, 0, NULL, 0 }
};

struct arguments
{
  const char *omapi_address;
  const unsigned char *omapi_secret;
  const char *omapi_secret_keyname;
  const char *omapi_secret_algo;
  int omapi_port;
  int http_port;
  int foreground;
  int verbose;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  const char *invalid_port_msg = "Invalid port number, must be [0,65535]";

  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'v':
      arguments->verbose = 1;
      break;
    case 'p':
      arguments->omapi_port = strtonum(arg, 1, 65535, &invalid_port_msg);
      break;
    case 'a':
      arguments->omapi_address = arg;
      break;
    case 'k':
      arguments->omapi_secret_keyname = arg;
      break;
    case 's':
      arguments->omapi_secret = (const unsigned char*)arg;
      break;
    case 'e':
      arguments->omapi_secret_algo = arg;
      break;
    case 't':
      arguments->http_port = strtonum(arg, 1, 65535, &invalid_port_msg);
      break;
    case 'f':
      arguments->foreground = 1;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

int main(int argc, char *argv[]) {
  struct dcd_ctx *ctx;
  struct arguments arguments;
  pid_t pid = -1;
  pid_t sid = -1;
  
  arguments.verbose = 0;
  arguments.omapi_port = OMAPI_DEFAULT_PORT;
  arguments.omapi_secret = NULL;
  arguments.omapi_secret_keyname = NULL;
  arguments.omapi_secret_algo = OMAPI_DEFAULT_SECRET_ALGO;
  arguments.omapi_address = OMAPI_DEFAULT_ADDR;
  arguments.http_port = HTTP_DEFAULT_PORT;
  arguments.foreground = 0;

  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  if (!arguments.foreground) {
    /* Spawn daemoized process */
    pid = fork();
    if (pid < 0) {
      fprintf(stderr, "Fork to process daemon failed: %s\n", strerror(errno));
      exit(1);
    }
    
    /* Finish up */
    if (pid > 0) {
      exit(0);
    }
    
    umask(0);
    sid = setsid();
    if (sid < 0) {
      fprintf(stderr, "Failed to set sid: %s\n", strerror(errno));
      exit(1);
    }
    
    chdir("/tmp");
  }
    
  ctx = dcd_init(arguments.omapi_address, arguments.omapi_port,
		 arguments.omapi_secret_keyname,
		 arguments.omapi_secret_algo,
		 arguments.omapi_secret,
		 arguments.http_port);

  if (ctx == NULL) {
    fprintf(stderr, "Failed to initialize dcd context, shutting down...\n");
    exit(1);
  }

  /* Go off into REM sleep...... */
  while (1) {
    sleep(1);
  }

  return 0;
}
