// Hash CLI {{{
//
// Exposes the sfinx hash wrappers to the openssl anchor test
//   hash <224|256|384|512>   read stdin, print the SHA3 hex
//   hash shake <bytes>       read stdin, print the SHAKE256 hex
// This is the only place the wrappers and openssl meet

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/sfinx.c"

static void print_hex(const uint8_t *in, size_t len) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    putchar(digits[in[i] >> 4]);
    putchar(digits[in[i] & 0x0f]);
  }
  putchar('\n');
}

static int read_stdin(uint8_t **out, size_t *out_len) {
  size_t   cap = 4096;
  size_t   len = 0;
  uint8_t *buf = malloc(cap);
  if (!buf) {
    return 0;
  }
  for (;;) {
    if (len == cap) {
      size_t   next_cap = cap * 2;
      uint8_t *next     = realloc(buf, next_cap);
      if (!next) {
        free(buf);
        return 0;
      }
      buf = next;
      cap = next_cap;
    }
    len += fread(buf + len, 1, cap - len, stdin);
    if (feof(stdin)) {
      break;
    }
  }
  *out     = buf;
  *out_len = len;
  return 1;
}

int main(int argc, char **argv) {
  uint8_t *in     = NULL;
  size_t   in_len = 0;

  if (argc == 3 && strcmp(argv[1], "shake") == 0) {
    char    *end     = NULL;
    long     out_len = strtol(argv[2], &end, 10);
    uint8_t *out;
    if (!end || *end != '\0' || out_len < 0 || out_len > (1 << 20)) {
      fprintf(stderr, "usage: hash shake <bytes>\n");
      return 2;
    }
    if (!read_stdin(&in, &in_len)) {
      fprintf(stderr, "hash: out of memory\n");
      return 2;
    }
    out = malloc((size_t)out_len > 0 ? (size_t)out_len : 1);
    if (!out) {
      free(in);
      fprintf(stderr, "hash: out of memory\n");
      return 2;
    }
    _sfinx_shake256(in, in_len, out, (size_t)out_len);
    print_hex(out, (size_t)out_len);
    free(out);
    free(in);
    return 0;
  }

  if (argc == 2) {
    char      *end  = NULL;
    long       bits = strtol(argv[1], &end, 10);
    sfinx_hash hash = (sfinx_hash)bits;
    uint8_t    out[SFINX_HASH_LEN_MAX];
    if (!end || *end != '\0' || sfinx_hash_len(hash) == 0) {
      fprintf(stderr, "usage: hash <224|256|384|512>\n");
      return 2;
    }
    if (!read_stdin(&in, &in_len)) {
      fprintf(stderr, "hash: out of memory\n");
      return 2;
    }
    _sfinx_hash(hash, in, in_len, out);
    print_hex(out, sfinx_hash_len(hash));
    free(in);
    return 0;
  }

  fprintf(stderr, "usage: hash <224|256|384|512>\n       hash shake <bytes>\n");
  return 2;
}
// }}}

// vim:fdm=marker:fdl=0
