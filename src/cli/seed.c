#include <cofyc/argparse.h>
#include <stdio.h>
#include <stdlib.h>

#include "registry.h"
#include "sfinx.h"
#include "util/file.h"

static int cmd_seed(int argc, const char **argv) {
  const char *out_file = NULL;
  int         force    = 0;
  size_t      length   = 32;
  uint8_t    *seed;
  int         rc = 0;

  static const char *const usages[] = {
      "sfinx seed [length] [-o file]",
      NULL,
  };
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('o', "out", &out_file, "write the seed to a file", NULL, 0, 0),
      OPT_BOOLEAN(0, "force", &force, "overwrite an existing file", NULL, 0, 0),
      OPT_END(),
  };
  struct argparse argparse;
  argparse_init(&argparse, options, usages, 0);
  argparse_describe(&argparse, "\nGenerate a random seed", NULL);
  argc = argparse_parse(&argparse, argc, argv);

  if (argc > 1) {
    fprintf(stderr, "sfinx: seed: too many arguments\n");
    return 1;
  }
  if (argc == 1) {
    char         *end = NULL;
    unsigned long v   = strtoul(argv[0], &end, 10);
    if (!end || *end != '\0' || v == 0 || v > SFINX_SEED_LEN_MAX) {
      fprintf(stderr, "sfinx: seed: invalid length: %s\n", argv[0]);
      return 1;
    }
    length = (size_t)v;
  }

  seed = malloc(length);
  if (!seed) {
    fprintf(stderr, "sfinx: seed: out of memory\n");
    return 1;
  }
  if (sfinx_random_bytes(seed, length) != SFINX_OK) {
    fprintf(stderr, "sfinx: seed: %s\n", sfinx_strerror(SFINX_ERR_RANDOM));
    free(seed);
    return 1;
  }

  if (out_file) {
    if (util_file_write(out_file, seed, length, 0600, force) != 0) {
      fprintf(stderr, "sfinx: seed: cannot write %s\n", out_file);
      rc = 1;
    }
  } else if (fwrite(seed, 1, length, stdout) != length) {
    rc = 1;
  }
  free(seed);
  return rc;
}

static struct cli_command seed_command = {
    .names       = (const char *const[]){"seed", NULL},
    .display     = "seed",
    .description = "Generate a random seed",
    .help        = "sfinx seed [length] [-o file]",
    .fn          = cmd_seed,
};

__attribute__((constructor)) static void seed_register(void) {
  cli_command_register(&seed_command);
}
