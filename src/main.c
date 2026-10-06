#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>

#include "cli/registry.h"

int main(int argc, char *argv[]) {
  const char *prog = basename(argv[0]);

  cli_main_fn fn = cli_find(prog);
  if (fn) return fn(argc, argv);

  // Not argv[0], see if it's given as subcommand
  if (argc > 1 && (fn = cli_find(argv[1]))) {
    char **shifted = malloc(sizeof(char *) * (size_t)argc);
    if (!shifted) {
      fprintf(stderr, "out of memory\n");
      return 1;
    }
    shifted[0] = argv[1];
    for (int i = 2; i < argc; i++) shifted[i - 1] = argv[i];
    int rc = fn(argc - 1, shifted);
    free(shifted);
    return rc;
  }

  fprintf(stderr, "%s: unknown command: %s\n", argv[0], prog);
  fprintf(stderr, "available commands: %s\n", cli_registered());
  return 1;
}
