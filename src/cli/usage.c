#include "usage.h"

#include <stdio.h>

#include "registry.h"

void cli_print_global_usage(void) {
  struct cli_command *command;
  fprintf(stdout, "usage: sfinx <command> [options]\n\ncommands:\n");
  for (command = cli_commands; command; command = command->next) {
    fprintf(stdout, "  %-12s %s\n", command->display, command->description);
  }
}
