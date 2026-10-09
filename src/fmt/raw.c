#include <stdlib.h>
#include <string.h>

#include "../sfinx.h"

// raw format {{{
//
// The whole file is raw key material, no marker, so it is never auto-detected
//   decode reads a seed, encode writes the seed if present else the public key

static sfinx_status raw_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  uint8_t *seed;
  if (len == 0) {
    return SFINX_ERR_FORMAT;
  }
  seed = malloc(len);
  if (!seed) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(seed, data, len);
  out->seed     = seed;
  out->seed_len = len;
  return SFINX_OK;
}

static size_t raw_encode_len(const sfinx_key *key) {
  if (key->seed) return key->seed_len;
  if (key->pub) return key->pub_len;
  return 0;
}

static sfinx_status raw_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
  const uint8_t *src;
  size_t         len;
  if (key->seed) {
    src = key->seed;
    len = key->seed_len;
  } else if (key->pub) {
    src = key->pub;
    len = key->pub_len;
  } else {
    return SFINX_ERR_ARGS;
  }
  if (cap < len) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(out, src, len);
  if (len_out) {
    *len_out = len;
  }
  return SFINX_OK;
}

static sfinx_format raw_format = {
    .name       = "raw",
    .detect     = NULL,
    .decode     = raw_decode,
    .encode_len = raw_encode_len,
    .encode     = raw_encode,
};

__attribute__((constructor)) static void raw_register(void) {
  sfinx_format_register(&raw_format);
}
// }}}

// vim:fdm=marker:fdl=0
