#include <stddef.h>
#include <stdio.h>

#include "registry.h"
#include "sfinx.h"

static int cmd_version(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  fprintf(stdout, "%s\n", sfinx_version());
  return 0;
}

static struct cli_command version_command = {
    .names       = (const char *const[]){"version", NULL},
    .display     = "version",
    .description = "Show the version",
    .help        = "sfinx version",
    .fn          = cmd_version,
};

__attribute__((constructor)) static void version_register(void) {
  cli_command_register(&version_command);
}
