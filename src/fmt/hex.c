#include <stdlib.h>

#include "../sfinx.h"

// hex format {{{
//
// Lowercase hex text, no marker, so it is never auto-detected
//   key decode reads a seed, key encode writes the seed if present else the public key
//   signature decode parses hex, encode emits hex

static int hex_val(uint8_t c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static void hex_put(uint8_t *out, const uint8_t *in, size_t in_len) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < in_len; i++) {
    out[i * 2]     = (uint8_t)digits[(in[i] >> 4) & 0x0f];
    out[i * 2 + 1] = (uint8_t)digits[in[i] & 0x0f];
  }
}

static sfinx_status hex_get(const uint8_t *in, size_t in_len, uint8_t *out, size_t cap, size_t *out_len) {
  size_t n;
  if (in_len % 2 != 0) {
    return SFINX_ERR_FORMAT;
  }
  n = in_len / 2;
  if (cap < n) {
    return SFINX_ERR_NOSPACE;
  }
  for (size_t i = 0; i < n; i++) {
    int hi = hex_val(in[i * 2]);
    int lo = hex_val(in[i * 2 + 1]);
    if (hi < 0 || lo < 0) {
      return SFINX_ERR_FORMAT;
    }
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  if (out_len) {
    *out_len = n;
  }
  return SFINX_OK;
}

static sfinx_status hex_key_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  sfinx_status status;
  if (len == 0 || len / 2 > SFINX_SEED_LEN_MAX) {
    return SFINX_ERR_FORMAT;
  }
  out->seed = malloc(len / 2 + 1);
  if (!out->seed) {
    return SFINX_ERR_NOSPACE;
  }
  status = hex_get(data, len, out->seed, len / 2, &out->seed_len);
  if (status != SFINX_OK) {
    free(out->seed);
    out->seed = NULL;
  }
  return status;
}

static size_t hex_key_encode_len(const sfinx_key *key) {
  if (key->seed) return key->seed_len * 2;
  if (key->pub) return key->pub_len * 2;
  return 0;
}

static sfinx_status hex_key_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
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
  if (cap < len * 2) {
    return SFINX_ERR_NOSPACE;
  }
  hex_put(out, src, len);
  if (len_out) {
    *len_out = len * 2;
  }
  return SFINX_OK;
}

static sfinx_status hex_sig_decode(const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *len_out) {
  return hex_get(data, len, out, cap, len_out);
}

static size_t hex_sig_encode_len(const uint8_t *sig, size_t sig_len) {
  (void)sig;
  return sig_len * 2;
}

static sfinx_status hex_sig_encode(const uint8_t *sig, size_t sig_len, uint8_t *out, size_t cap, size_t *len_out) {
  if (cap < sig_len * 2) {
    return SFINX_ERR_NOSPACE;
  }
  hex_put(out, sig, sig_len);
  if (len_out) {
    *len_out = sig_len * 2;
  }
  return SFINX_OK;
}

static sfinx_format hex_format = {
    .name           = "hex",
    .key_decode     = hex_key_decode,
    .key_encode_len = hex_key_encode_len,
    .key_encode     = hex_key_encode,
    .sig_decode     = hex_sig_decode,
    .sig_encode_len = hex_sig_encode_len,
    .sig_encode     = hex_sig_encode,
};

__attribute__((constructor)) static void hex_register(void) {
  sfinx_format_register(&hex_format);
}
// }}}

// hexpub format {{{
//
// A public key as hex text, no marker, so it is never auto-detected
//   decode infers the hash from the length, encode emits hex

static sfinx_hash hexpub_hash_for_len(size_t len) {
  static const sfinx_hash hashes[] = {SFINX_HASH_224, SFINX_HASH_256, SFINX_HASH_384, SFINX_HASH_512};
  for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
    if (sfinx_hash_len(hashes[i]) == len) return hashes[i];
  }
  return 0;
}

static sfinx_status hexpub_key_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  sfinx_status status;
  size_t       n;
  sfinx_hash   hash;
  if (len % 2 != 0) {
    return SFINX_ERR_FORMAT;
  }
  n    = len / 2;
  hash = hexpub_hash_for_len(n);
  if (hash == 0) {
    return SFINX_ERR_FORMAT;
  }
  out->pub = malloc(n);
  if (!out->pub) {
    return SFINX_ERR_NOSPACE;
  }
  status = hex_get(data, len, out->pub, n, &out->pub_len);
  if (status != SFINX_OK) {
    free(out->pub);
    out->pub = NULL;
    return status;
  }
  out->hash = hash;
  return SFINX_OK;
}

static size_t hexpub_key_encode_len(const sfinx_key *key) {
  return key->pub ? key->pub_len * 2 : 0;
}

static sfinx_status hexpub_key_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
  if (!key->pub) {
    return SFINX_ERR_ARGS;
  }
  if (cap < key->pub_len * 2) {
    return SFINX_ERR_NOSPACE;
  }
  hex_put(out, key->pub, key->pub_len);
  if (len_out) {
    *len_out = key->pub_len * 2;
  }
  return SFINX_OK;
}

static sfinx_format hexpub_format = {
    .name           = "hexpub",
    .key_decode     = hexpub_key_decode,
    .key_encode_len = hexpub_key_encode_len,
    .key_encode     = hexpub_key_encode,
};

__attribute__((constructor)) static void hexpub_register(void) {
  sfinx_format_register(&hexpub_format);
}
// }}}

// vim:fdm=marker:fdl=0
