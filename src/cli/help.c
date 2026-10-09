#include <stdio.h>

#include "registry.h"

int main_help(int argc, char *argv[]) {
  (void)argc;
  (void)argv;
  fprintf(stdout, "hi there\n");
  return 0;
}

__attribute__((constructor)) static void register_help(void) {
  cli_register("help", main_help);
}
