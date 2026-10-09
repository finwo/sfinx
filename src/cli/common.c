#include "common.h"

#include <stdlib.h>
#include <string.h>

#include "sfinx.h"
#include "util/file.h"

int cli_read_message(const char *message, const char *file, uint8_t **out, size_t *len_out) {
  uint8_t *buf;
  size_t   len;
  if (message) {
    len = strlen(message);
    buf = malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, message, len + 1);
    *out     = buf;
    *len_out = len;
    return 0;
  }
  return util_file_read(file, out, len_out);
}

int cli_seed_length(const char *text, size_t *len_out) {
  char         *end = NULL;
  unsigned long v;
  if (!text) {
    *len_out = CLI_SEED_LEN_DEFAULT;
    return 0;
  }
  v = strtoul(text, &end, 10);
  if (!end || *end != '\0' || v == 0 || v > SFINX_SEED_LEN_MAX) {
    return -1;
  }
  *len_out = (size_t)v;
  return 0;
}

sfinx_status cli_seed_random(size_t len, uint8_t **out) {
  uint8_t     *seed = malloc(len);
  sfinx_status status;
  if (!seed) {
    return SFINX_ERR_NOSPACE;
  }
  status = sfinx_random_bytes(seed, len);
  if (status != SFINX_OK) {
    free(seed);
    return status;
  }
  *out = seed;
  return SFINX_OK;
}

sfinx_status cli_key_derive(sfinx_key *key, size_t path_len) {
  size_t       len;
  uint8_t     *pub;
  sfinx_status status;

  if (!key->seed) {
    return sfinx_key_derive(key);
  }
  len = sfinx_hash_len(key->hash);
  if (len == 0) {
    return SFINX_ERR_ARGS;
  }
  free(key->pub);
  key->pub     = NULL;
  key->pub_len = 0;
  if (path_len != 0) {
    return sfinx_key_derive(key);
  }
  pub = malloc(len);
  if (!pub) {
    return SFINX_ERR_NOSPACE;
  }
  status = sfinx_single_public_key(key->hash, key->seed, key->seed_len, pub, len, NULL);
  if (status != SFINX_OK) {
    free(pub);
    return status;
  }
  key->pub     = pub;
  key->pub_len = len;
  return SFINX_OK;
}

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int cli_hex_decode(const char *hex, uint8_t **out, size_t *len_out) {
  size_t   len = strlen(hex);
  size_t   n;
  uint8_t *buf;
  if (len % 2 != 0) return -1;
  n   = len / 2;
  buf = malloc(n + 1);
  if (!buf) return -1;
  for (size_t i = 0; i < n; i++) {
    int hi = hexval(hex[i * 2]);
    int lo = hexval(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      free(buf);
      return -1;
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out     = buf;
  *len_out = n;
  return 0;
}
