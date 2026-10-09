#include <cofyc/argparse.h>
#include <stdio.h>

#include "cli/registry.h"
#include "sfinx.h"

static const char *const usages[] = {
    "sfinx [global] command [local]",
    "sfinx help",
    "sfinx --version",
    NULL,
};

int main(int argc, char **argv) {
  struct cli_command *command;
  struct argparse     argparse;
  int                 version = 0;

  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_BOOLEAN('V', "version", &version, "show version and exit", NULL, 0, 0),
      OPT_END(),
  };

  argparse_init(&argparse, options, usages, ARGPARSE_STOP_AT_NON_OPTION);
  argparse_describe(&argparse, NULL, command_list);
  argc = argparse_parse(&argparse, argc, (const char **)argv);

  if (version) {
    fprintf(stdout, "%s\n", sfinx_version());
    return 0;
  }
  if (argc < 1) {
    argparse_usage(&argparse);
    return 1;
  }

  command = cli_command_find(argv[0]);
  if (!command) {
    fprintf(stderr, "sfinx: unknown command: %s\n", argv[0]);
    return 1;
  }
  return command->fn(argc, (const char **)argv);
}
