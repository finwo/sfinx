#include <stddef.h>

#include "registry.h"
#include "usage.h"

static int cmd_help(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  cli_print_global_usage();
  return 0;
}

static struct cli_command help_command = {
    .names       = (const char *const[]){"help", NULL},
    .display     = "help",
    .description = "Show this help",
    .help        = "sfinx help",
    .fn          = cmd_help,
};

__attribute__((constructor)) static void help_register(void) {
  cli_command_register(&help_command);
}
