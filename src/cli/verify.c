#include <cofyc/argparse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "registry.h"
#include "sfinx.h"
#include "util/file.h"

static int cmd_verify(int argc, const char **argv) {
  const char  *key_file     = NULL;
  const char  *key_format   = NULL;
  const char  *format       = NULL;
  const char  *signature    = NULL;
  const char  *sig_file     = NULL;
  const char  *message      = NULL;
  const char  *msg_file     = NULL;
  int          hash         = 0;
  uint8_t     *key_data     = NULL;
  uint8_t     *msg_data     = NULL;
  uint8_t     *sig_data     = NULL;
  uint8_t     *raw_sig      = NULL;
  size_t       key_len      = 0;
  size_t       msg_len      = 0;
  size_t       sig_data_len = 0;
  size_t       raw_len      = 0;
  sfinx_key    key;
  sfinx_status status;
  int          rc = 1;

  static const char *const usages[] = {
      "sfinx verify -k keyfile [-L bits] [-s signature | -S signature-file] [-m message | -M message-file] "
      "[--key-fmt fmt] [--sig-fmt fmt]",
      NULL,
  };
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING('k', "key-file", &key_file, "public key file", NULL, 0, 0),
      OPT_STRING(0, "key-fmt", &key_format, "key format, auto by default", NULL, 0, 0),
      OPT_STRING(0, "sig-fmt", &format, "signature format, auto by default", NULL, 0, 0),
      OPT_INTEGER('L', "hash", &hash, "expected hash size", NULL, 0, 0),
      OPT_STRING('s', "signature", &signature, "signature as hex", NULL, 0, 0),
      OPT_STRING('S', "signature-file", &sig_file, "signature file, - for stdin", NULL, 0, 0),
      OPT_STRING('m', "message", &message, "message string", NULL, 0, 0),
      OPT_STRING('M', "message-file", &msg_file, "message file, - for stdin", NULL, 0, 0),
      OPT_END(),
  };
  struct argparse argparse;
  argparse_init(&argparse, options, usages, 0);
  argparse_describe(&argparse, "\nVerify a message signature", NULL);
  argc = argparse_parse(&argparse, argc, argv);

  sfinx_key_init(&key);

  if (argc > 0) {
    fprintf(stderr, "sfinx: verify: unexpected argument: %s\n", argv[0]);
    return 1;
  }
  if (!key_file) {
    fprintf(stderr, "sfinx: verify: missing --key-file\n");
    return 1;
  }
  if (signature && sig_file) {
    fprintf(stderr, "sfinx: verify: --signature and --signature-file are exclusive\n");
    return 1;
  }
  if (message && msg_file) {
    fprintf(stderr, "sfinx: verify: --message and --message-file are exclusive\n");
    return 1;
  }

  int msg_stdin = !message && (!msg_file || strcmp(msg_file, "-") == 0);
  int sig_stdin = !signature && (!sig_file || strcmp(sig_file, "-") == 0);
  if (msg_stdin && sig_stdin) {
    fprintf(stderr, "sfinx: verify: message and signature cannot both come from stdin\n");
    return 1;
  }

  if (util_file_read(key_file, &key_data, &key_len) != 0) {
    fprintf(stderr, "sfinx: verify: cannot read %s\n", key_file);
    goto done;
  }
  status = sfinx_key_decode(key_data, key_len, key_format, &key);
  if (status != SFINX_OK && !key_format) {
    status = sfinx_key_decode(key_data, key_len, "rawpub", &key);
  }
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: verify: cannot decode %s: %s\n", key_file, sfinx_strerror(status));
    goto done;
  }
  if (sfinx_key_derive(&key) != SFINX_OK || !key.pub) {
    fprintf(stderr, "sfinx: verify: key has no public key\n");
    goto done;
  }

  if (cli_read_message(message, msg_file, &msg_data, &msg_len) != 0) {
    fprintf(stderr, "sfinx: verify: cannot read the message\n");
    goto done;
  }

  if (signature) {
    if (cli_hex_decode(signature, &raw_sig, &raw_len) != 0) {
      fprintf(stderr, "sfinx: verify: invalid signature hex\n");
      goto done;
    }
  } else {
    if (util_file_read(sig_file, &sig_data, &sig_data_len) != 0) {
      fprintf(stderr, "sfinx: verify: cannot read the signature\n");
      goto done;
    }
    raw_sig = malloc(sig_data_len + 1);
    if (!raw_sig) {
      fprintf(stderr, "sfinx: verify: out of memory\n");
      goto done;
    }
    status = sfinx_sig_decode(sig_data, sig_data_len, format, raw_sig, sig_data_len, &raw_len);
    if (status != SFINX_OK) {
      fprintf(stderr, "sfinx: verify: cannot decode the signature: %s\n", sfinx_strerror(status));
      goto done;
    }
  }

  if (hash != 0) {
    sfinx_hash sig_hash;
    size_t     sig_path;
    if (sfinx_signature_info(raw_sig, raw_len, &sig_hash, &sig_path) != SFINX_OK || (int)sig_hash != hash) {
      fprintf(stderr, "sfinx: verify: signature is not %d-bit\n", hash);
      goto done;
    }
  }

  if (sfinx_verify(key.pub, key.pub_len, msg_data, msg_len, raw_sig, raw_len) == SFINX_OK) {
    fprintf(stdout, "OK\n");
    rc = 0;
  } else {
    fprintf(stdout, "FAIL\n");
    rc = 1;
  }

done:
  free(key_data);
  free(msg_data);
  free(sig_data);
  free(raw_sig);
  sfinx_key_free(&key);
  return rc;
}

static struct cli_command verify_command = {
    .names       = (const char *const[]){"verify", NULL},
    .display     = "verify",
    .description = "Verify a message signature",
    .help =
        "sfinx verify -k keyfile [-L bits] [-s signature | -S signature-file] [-m message | -M message-file] "
        "[--key-fmt fmt] [--sig-fmt fmt]",
    .fn = cmd_verify,
};

__attribute__((constructor)) static void verify_register(void) {
  cli_command_register(&verify_command);
}
