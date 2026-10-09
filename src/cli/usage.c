#include "usage.h"

#include <stdio.h>

#include "registry.h"

void cli_print_global_usage(void) {
  fprintf(stdout, "usage: sfinx <command> [options]\n\n%s", command_list ? command_list : "");
}
