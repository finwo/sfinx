#include <cofyc/argparse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "registry.h"
#include "sfinx.h"
#include "util/file.h"

static int cmd_sign(int argc, const char **argv) {
  const char  *key_file   = NULL;
  const char  *key_format = NULL;
  const char  *out_file   = NULL;
  const char  *format     = NULL;
  const char  *path_hex   = NULL;
  const char  *message    = NULL;
  const char  *msg_file   = NULL;
  int          hash       = 0;
  int          path_len   = SFINX_PATH_LEN_DEFAULT;
  int          force      = 0;
  uint8_t     *key_data   = NULL;
  uint8_t     *msg_data   = NULL;
  uint8_t     *path       = NULL;
  uint8_t     *sig        = NULL;
  uint8_t     *encoded    = NULL;
  size_t       key_len    = 0;
  size_t       msg_len    = 0;
  size_t       path_bytes = 0;
  size_t       sig_len    = 0;
  size_t       enc_len    = 0;
  sfinx_key    key;
  sfinx_status status;
  int          rc = 1;

  static const char *const usages[] = {
      "sfinx sign -k keyfile [-L hash] [-p path-len | -P path] [-m message | -M message-file] [--key-fmt fmt] "
      "[--sig-fmt fmt] [-o file] [-F]",
      NULL,
  };
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('k', "key-file", &key_file, "secret key file", NULL, 0, 0),
      OPT_STRING(0, "key-fmt", &key_format, "key format, auto by default", NULL, 0, 0),
      OPT_INTEGER('L', "hash", &hash, "hash size 224/256/384/512", NULL, 0, 0),
      OPT_INTEGER('p', "path-len", &path_len, "random path length", NULL, 0, 0),
      OPT_STRING('P', "path", &path_hex, "explicit path as hex", NULL, 0, 0),
      OPT_STRING('m', "message", &message, "message string", NULL, 0, 0),
      OPT_STRING('M', "message-file", &msg_file, "message file, - for stdin", NULL, 0, 0),
      OPT_STRING(0, "sig-fmt", &format, "signature format, hex on stdout and raw to a file by default", NULL, 0, 0),
      OPT_STRING('o', "out", &out_file, "signature file, - for stdout", NULL, 0, 0),
      OPT_BOOLEAN('F', "force", &force, "overwrite an existing output file", NULL, 0, 0),
      OPT_END(),
  };
  struct argparse argparse;
  argparse_init(&argparse, options, usages, 0);
  argparse_describe(&argparse, "\nSign a message", NULL);
  argc = argparse_parse(&argparse, argc, argv);

  sfinx_key_init(&key);

  if (argc > 0) {
    fprintf(stderr, "sfinx: sign: unexpected argument: %s\n", argv[0]);
    return 1;
  }
  if (!key_file) {
    fprintf(stderr, "sfinx: sign: missing --key-file\n");
    return 1;
  }
  if (message && msg_file) {
    fprintf(stderr, "sfinx: sign: --message and --message-file are exclusive\n");
    return 1;
  }

  if (util_file_read(key_file, &key_data, &key_len) != 0) {
    fprintf(stderr, "sfinx: sign: cannot read %s\n", key_file);
    goto done;
  }
  status = sfinx_key_decode(key_data, key_len, key_format, &key);
  if (status != SFINX_OK && !key_format) {
    status = sfinx_key_decode(key_data, key_len, "raw", &key);
  }
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: sign: cannot decode %s: %s\n", key_file, sfinx_strerror(status));
    goto done;
  }
  if (!key.seed) {
    fprintf(stderr, "sfinx: sign: key has no seed\n");
    goto done;
  }
  if (hash != 0) {
    key.hash = (sfinx_hash)hash;
  }
  if (sfinx_hash_len(key.hash) == 0) {
    fprintf(stderr, "sfinx: sign: invalid hash size: %d\n", (int)key.hash);
    goto done;
  }

  if (cli_read_message(message, msg_file, &msg_data, &msg_len) != 0) {
    fprintf(stderr, "sfinx: sign: cannot read the message\n");
    goto done;
  }

  if (path_hex) {
    if (cli_hex_decode(path_hex, &path, &path_bytes) != 0 || !sfinx_path_len_valid(path_bytes)) {
      fprintf(stderr, "sfinx: sign: invalid path\n");
      goto done;
    }
  } else {
    if (path_len <= 0 || !sfinx_path_len_valid((size_t)path_len)) {
      fprintf(stderr, "sfinx: sign: invalid path length: %d\n", path_len);
      goto done;
    }
    path_bytes = (size_t)path_len;
    path       = malloc(path_bytes);
    if (!path) {
      fprintf(stderr, "sfinx: sign: out of memory\n");
      goto done;
    }
    if (sfinx_random_bytes(path, path_bytes) != SFINX_OK) {
      fprintf(stderr, "sfinx: sign: %s\n", sfinx_strerror(SFINX_ERR_RANDOM));
      goto done;
    }
  }

  sig_len = sfinx_signature_len(key.hash, path_bytes);
  sig     = malloc(sig_len);
  if (!sig) {
    fprintf(stderr, "sfinx: sign: out of memory\n");
    goto done;
  }
  status = sfinx_tree_sign(key.hash, key.seed, key.seed_len, path, path_bytes, msg_data, msg_len, sig, sig_len, NULL);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: sign: %s\n", sfinx_strerror(status));
    goto done;
  }

  if (!format) {
    format = (out_file && strcmp(out_file, "-") != 0) ? "raw" : "hex";
  }
  enc_len = sfinx_sig_encode_len(sig, sig_len, format);
  if (enc_len == 0) {
    fprintf(stderr, "sfinx: sign: unknown signature format: %s\n", format);
    goto done;
  }
  encoded = malloc(enc_len);
  if (!encoded) {
    fprintf(stderr, "sfinx: sign: out of memory\n");
    goto done;
  }
  status = sfinx_sig_encode(sig, sig_len, format, encoded, enc_len, &enc_len);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: sign: cannot encode: %s\n", sfinx_strerror(status));
    goto done;
  }
  if (util_file_write(out_file, encoded, enc_len, 0644, force) != 0) {
    fprintf(stderr, "sfinx: sign: cannot write %s\n", out_file ? out_file : "-");
    goto done;
  }
  rc = 0;

done:
  free(key_data);
  free(msg_data);
  free(path);
  free(sig);
  free(encoded);
  sfinx_key_free(&key);
  return rc;
}

static struct cli_command sign_command = {
    .names       = (const char *const[]){"sign", NULL},
    .display     = "sign",
    .description = "Sign a message",
    .help =
        "sfinx sign -k keyfile [-L hash] [-p path-len | -P path] [-m message | -M message-file] [--key-fmt fmt] "
        "[--sig-fmt fmt] [-o file] [-F]",
    .fn = cmd_sign,
};

__attribute__((constructor)) static void sign_register(void) {
  cli_command_register(&sign_command);
}
