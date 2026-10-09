#include <cofyc/argparse.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "registry.h"
#include "sfinx.h"
#include "util/file.h"

static int cmd_printkey(int argc, const char **argv) {
  const char  *key_file    = NULL;
  const char  *out_file    = NULL;
  const char  *format      = "hdr";
  const char  *in_format   = NULL;
  int          hash        = 0;
  int          public_only = 0;
  int          single      = 0;
  int          force       = 0;
  uint8_t     *data        = NULL;
  uint8_t     *out         = NULL;
  size_t       data_len    = 0;
  size_t       out_len     = 0;
  sfinx_key    key;
  sfinx_status status;
  int          rc = 0;

  static const char *const usages[] = {
      "sfinx printkey -k file [-L hash] [--in-fmt fmt] [--out-fmt fmt] [--single] [-o file] [--public-only] [--force]",
      NULL,
  };
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('k', "key-file", &key_file, "key file to read", NULL, 0, 0),
      OPT_STRING(0, "out-fmt", &format, "output format (default hdr)", NULL, 0, 0),
      OPT_STRING(0, "in-fmt", &in_format, "input format (default auto)", NULL, 0, 0),
      OPT_INTEGER('L', "hash", &hash, "hash size (224/256/384/512)", NULL, 0, 0),
      OPT_STRING('o', "out", &out_file, "write to a file instead of stdout", NULL, 0, 0),
      OPT_BOOLEAN(0, "public-only", &public_only, "output only the public key", NULL, 0, 0),
      OPT_BOOLEAN(0, "single", &single, "single-key mode, derive the N = 0 public key", NULL, 0, 0),
      OPT_BOOLEAN(0, "force", &force, "overwrite an existing file", NULL, 0, 0),
      OPT_END(),
  };
  struct argparse argparse;
  argparse_init(&argparse, options, usages, 0);
  argparse_describe(&argparse, "\nPrint or convert a key file", NULL);
  argc = argparse_parse(&argparse, argc, argv);

  if (argc > 0) {
    fprintf(stderr, "sfinx: printkey: unexpected argument: %s\n", argv[0]);
    return 1;
  }
  if (!key_file) {
    fprintf(stderr, "sfinx: printkey: missing --key-file\n");
    return 1;
  }
  if (util_file_read(key_file, &data, &data_len) != 0) {
    fprintf(stderr, "sfinx: printkey: cannot read %s\n", key_file);
    return 1;
  }

  status = sfinx_key_decode(data, data_len, in_format, &key);
  free(data);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: printkey: cannot decode %s: %s\n", key_file, sfinx_strerror(status));
    return 1;
  }
  if (hash != 0) {
    key.hash = (sfinx_hash)hash;
  }
  if (sfinx_hash_len(key.hash) == 0) {
    fprintf(stderr, "sfinx: printkey: invalid hash size: %d\n", (int)key.hash);
    sfinx_key_free(&key);
    return 1;
  }
  status = cli_key_derive(&key, single);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: printkey: cannot derive public key: %s\n", sfinx_strerror(status));
    sfinx_key_free(&key);
    return 1;
  }
  if (public_only) {
    free(key.seed);
    key.seed     = NULL;
    key.seed_len = 0;
  }

  if (!sfinx_format_find(format)) {
    fprintf(stderr, "sfinx: printkey: unknown format: %s\n", format);
    sfinx_key_free(&key);
    return 1;
  }
  out_len = sfinx_key_encode_len(&key, format);
  if (out_len == 0) {
    fprintf(stderr, "sfinx: printkey: cannot encode key as %s\n", format);
    sfinx_key_free(&key);
    return 1;
  }
  out = malloc(out_len);
  if (!out) {
    fprintf(stderr, "sfinx: printkey: out of memory\n");
    sfinx_key_free(&key);
    return 1;
  }
  status = sfinx_key_encode(&key, format, out, out_len, &out_len);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: printkey: cannot encode: %s\n", sfinx_strerror(status));
    rc = 1;
  } else if (out_file) {
    if (util_file_write(out_file, out, out_len, key.seed ? 0600 : 0644, force) != 0) {
      fprintf(stderr, "sfinx: printkey: cannot write %s\n", out_file);
      rc = 1;
    }
  } else if (fwrite(out, 1, out_len, stdout) != out_len) {
    rc = 1;
  }
  free(out);
  sfinx_key_free(&key);
  return rc;
}

static struct cli_command printkey_command = {
    .names       = (const char *const[]){"printkey", NULL},
    .display     = "printkey",
    .description = "Print or convert a key file",
    .help =
        "sfinx printkey -k file [-L hash] [--in-fmt fmt] [--out-fmt fmt] [--single] [-o file] [--public-only] "
        "[--force]",
    .fn = cmd_printkey,
};

__attribute__((constructor)) static void printkey_register(void) {
  cli_command_register(&printkey_command);
}
