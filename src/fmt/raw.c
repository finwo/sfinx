#include <stdlib.h>
#include <string.h>

#include "../sfinx.h"

// raw format {{{
//
// The whole input is raw bytes, no marker, so it is never auto-detected
//   key decode reads a seed, key encode writes the seed if present else the public key
//   signature decode and encode are the identity

static sfinx_status raw_key_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  uint8_t *seed;
  if (len == 0 || len > SFINX_SEED_LEN_MAX) {
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

static size_t raw_key_encode_len(const sfinx_key *key) {
  if (key->seed) return key->seed_len;
  if (key->pub) return key->pub_len;
  return 0;
}

static sfinx_status raw_key_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
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

static sfinx_status raw_sig_decode(const uint8_t *data, size_t len, uint8_t *out, size_t cap, size_t *len_out) {
  if (cap < len) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(out, data, len);
  if (len_out) {
    *len_out = len;
  }
  return SFINX_OK;
}

static size_t raw_sig_encode_len(const uint8_t *sig, size_t sig_len) {
  (void)sig;
  return sig_len;
}

static sfinx_status raw_sig_encode(const uint8_t *sig, size_t sig_len, uint8_t *out, size_t cap, size_t *len_out) {
  return raw_sig_decode(sig, sig_len, out, cap, len_out);
}

static sfinx_format raw_format = {
    .name           = "raw",
    .key_decode     = raw_key_decode,
    .key_encode_len = raw_key_encode_len,
    .key_encode     = raw_key_encode,
    .sig_decode     = raw_sig_decode,
    .sig_encode_len = raw_sig_encode_len,
    .sig_encode     = raw_sig_encode,
};

__attribute__((constructor)) static void raw_register(void) {
  sfinx_format_register(&raw_format);
}
// }}}

// rawpub format {{{
//
// A bare public key of L bytes, no marker, so it is never auto-detected
//   decode infers the hash from the length, encode writes the public half

static sfinx_hash rawpub_hash_for_len(size_t len) {
  static const sfinx_hash hashes[] = {SFINX_HASH_224, SFINX_HASH_256, SFINX_HASH_384, SFINX_HASH_512};
  for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++) {
    if (sfinx_hash_len(hashes[i]) == len) return hashes[i];
  }
  return 0;
}

static sfinx_status rawpub_key_decode(const uint8_t *data, size_t len, sfinx_key *out) {
  sfinx_hash hash = rawpub_hash_for_len(len);
  if (hash == 0) {
    return SFINX_ERR_FORMAT;
  }
  out->pub = malloc(len);
  if (!out->pub) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(out->pub, data, len);
  out->pub_len = len;
  out->hash    = hash;
  return SFINX_OK;
}

static size_t rawpub_key_encode_len(const sfinx_key *key) {
  return key->pub ? key->pub_len : 0;
}

static sfinx_status rawpub_key_encode(const sfinx_key *key, uint8_t *out, size_t cap, size_t *len_out) {
  if (!key->pub) {
    return SFINX_ERR_ARGS;
  }
  if (cap < key->pub_len) {
    return SFINX_ERR_NOSPACE;
  }
  memcpy(out, key->pub, key->pub_len);
  if (len_out) {
    *len_out = key->pub_len;
  }
  return SFINX_OK;
}

static sfinx_format rawpub_format = {
    .name           = "rawpub",
    .key_decode     = rawpub_key_decode,
    .key_encode_len = rawpub_key_encode_len,
    .key_encode     = rawpub_key_encode,
};

__attribute__((constructor)) static void rawpub_register(void) {
  sfinx_format_register(&rawpub_format);
}
// }}}

// vim:fdm=marker:fdl=0
