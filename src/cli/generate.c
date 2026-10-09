#include <cofyc/argparse.h>
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "registry.h"
#include "sfinx.h"
#include "util/file.h"

// Pub path {{{
//
// The public half goes next to the key file
//   a `.key` suffix of any case becomes `.pub` in the same case, anything else has `.pub` appended

static int path_ends_in_key(const char *path, size_t len) {
  static const char suffix[] = ".key";
  if (len < 4) {
    return 0;
  }
  for (size_t i = 0; i < 4; i++) {
    if (tolower((unsigned char)path[len - 4 + i]) != suffix[i]) {
      return 0;
    }
  }
  return 1;
}

static char pub_char(char source, char lower) {
  return isupper((unsigned char)source) ? (char)toupper((unsigned char)lower) : lower;
}

static int cli_pub_path(const char *path, char **out) {
  size_t len = strlen(path);
  char  *buf;
  if (path_ends_in_key(path, len)) {
    buf = malloc(len + 1);
    if (!buf) {
      return -1;
    }
    memcpy(buf, path, len - 4);
    buf[len - 4] = '.';
    buf[len - 3] = pub_char(path[len - 3], 'p');
    buf[len - 2] = pub_char(path[len - 2], 'u');
    buf[len - 1] = pub_char(path[len - 1], 'b');
    buf[len]     = '\0';
    *out         = buf;
    return 0;
  }
  buf = malloc(len + 5);
  if (!buf) {
    return -1;
  }
  memcpy(buf, path, len);
  memcpy(buf + len, ".pub", 5);
  *out = buf;
  return 0;
}
// }}}

static int cmd_generate(int argc, const char **argv) {
  const char  *out_file = NULL;
  const char  *format   = "hdr";
  const char  *pub_format;
  int          hash     = 0;
  int          force    = 0;
  size_t       seed_len = CLI_SEED_LEN_DEFAULT;
  uint8_t     *seed     = NULL;
  uint8_t     *key_buf  = NULL;
  uint8_t     *pub_buf  = NULL;
  char        *pub_file = NULL;
  size_t       key_len  = 0;
  size_t       pub_len  = 0;
  sfinx_key    key;
  sfinx_status status;
  int          to_stdout;
  int          rc = 1;

  static const char *const usages[] = {
      "sfinx generate [length] [-L hash] [--out-fmt fmt] [-o file] [-F]",
      NULL,
  };
  struct argparse_option options[] = {
      OPT_HELP(),
      OPT_STRING(0, "out-fmt", &format, "hdr writes one file, raw and hex write a key file and a .pub file", NULL, 0,
                 0),
      OPT_INTEGER('L', "hash", &hash, "hash size 224/256/384/512", NULL, 0, 0),
      OPT_STRING('o', "out", &out_file, "key file, - for stdout", NULL, 0, 0),
      OPT_BOOLEAN('F', "force", &force, "overwrite existing files", NULL, 0, 0),
      OPT_END(),
  };
  struct argparse argparse;
  argparse_init(&argparse, options, usages, 0);
  argparse_describe(&argparse, "\nGenerate a seed and its public key", NULL);
  argc = argparse_parse(&argparse, argc, argv);

  sfinx_key_init(&key);

  if (argc > 1) {
    fprintf(stderr, "sfinx: generate: too many arguments\n");
    return 1;
  }
  if (strcmp(format, "hdr") == 0) {
    pub_format = NULL;
  } else if (strcmp(format, "raw") == 0) {
    pub_format = "rawpub";
  } else if (strcmp(format, "hex") == 0) {
    pub_format = "hexpub";
  } else {
    fprintf(stderr, "sfinx: generate: unknown format: %s\n", format);
    return 1;
  }
  if (cli_seed_length(argc == 1 ? argv[0] : NULL, &seed_len) != 0) {
    fprintf(stderr, "sfinx: generate: invalid length: %s\n", argv[0]);
    return 1;
  }

  status = cli_seed_random(seed_len, &seed);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: generate: %s\n", sfinx_strerror(status));
    return 1;
  }
  key.seed     = seed;
  key.seed_len = seed_len;
  seed         = NULL;
  key.hash     = hash != 0 ? (sfinx_hash)hash : SFINX_HASH_DEFAULT;
  if (sfinx_hash_len(key.hash) == 0) {
    fprintf(stderr, "sfinx: generate: invalid hash size: %d\n", hash);
    goto done;
  }
  status = sfinx_key_derive(&key);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: generate: cannot derive the public key: %s\n", sfinx_strerror(status));
    goto done;
  }

  to_stdout = !out_file || strcmp(out_file, "-") == 0;
  if (pub_format && !to_stdout) {
    if (cli_pub_path(out_file, &pub_file) != 0) {
      fprintf(stderr, "sfinx: generate: out of memory\n");
      goto done;
    }
  }
  if (!to_stdout && !force) {
    if (util_file_exists(out_file)) {
      fprintf(stderr, "sfinx: generate: %s exists\n", out_file);
      goto done;
    }
    if (pub_file && util_file_exists(pub_file)) {
      fprintf(stderr, "sfinx: generate: %s exists\n", pub_file);
      goto done;
    }
  }

  key_len = sfinx_key_encode_len(&key, format);
  if (key_len == 0) {
    fprintf(stderr, "sfinx: generate: cannot encode a key as %s\n", format);
    goto done;
  }
  key_buf = malloc(key_len);
  if (!key_buf) {
    fprintf(stderr, "sfinx: generate: out of memory\n");
    goto done;
  }
  status = sfinx_key_encode(&key, format, key_buf, key_len, &key_len);
  if (status != SFINX_OK) {
    fprintf(stderr, "sfinx: generate: cannot encode: %s\n", sfinx_strerror(status));
    goto done;
  }

  if (pub_file) {
    pub_len = sfinx_key_encode_len(&key, pub_format);
    pub_buf = malloc(pub_len);
    if (!pub_buf) {
      fprintf(stderr, "sfinx: generate: out of memory\n");
      goto done;
    }
    status = sfinx_key_encode(&key, pub_format, pub_buf, pub_len, &pub_len);
    if (status != SFINX_OK) {
      fprintf(stderr, "sfinx: generate: cannot encode the public key: %s\n", sfinx_strerror(status));
      goto done;
    }
  }

  if (util_file_write(out_file, key_buf, key_len, 0600, force) != 0) {
    fprintf(stderr, "sfinx: generate: cannot write %s\n", out_file ? out_file : "-");
    goto done;
  }
  if (pub_buf) {
    if (util_file_write(pub_file, pub_buf, pub_len, 0644, force) != 0) {
      fprintf(stderr, "sfinx: generate: cannot write %s\n", pub_file);
      goto done;
    }
  }
  rc = 0;

done:
  free(seed);
  free(key_buf);
  free(pub_buf);
  free(pub_file);
  sfinx_key_free(&key);
  return rc;
}

static struct cli_command generate_command = {
    .names       = (const char *const[]){"generate", NULL},
    .display     = "generate",
    .description = "Generate a seed and its public key",
    .help        = "sfinx generate [length] [-L hash] [--out-fmt fmt] [-o file] [-F]",
    .fn          = cmd_generate,
};

__attribute__((constructor)) static void generate_register(void) {
  cli_command_register(&generate_command);
}
