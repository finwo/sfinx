#include <stdio.h>
#include <string.h>

#include "cli/registry.h"
#include "cli/usage.h"
#include "sfinx.h"

int main(int argc, char **argv) {
  struct cli_command *command;

  if (argc < 2) {
    cli_print_global_usage();
    return 1;
  }
  if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
    cli_print_global_usage();
    return 0;
  }
  if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
    fprintf(stdout, "%s\n", sfinx_version());
    return 0;
  }

  command = cli_command_find(argv[1]);
  if (!command) {
    fprintf(stderr, "sfinx: unknown command: %s\n", argv[1]);
    cli_print_global_usage();
    return 1;
  }
  return command->fn(argc - 1, (const char **)(argv + 1));
}
