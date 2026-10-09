#include <stdlib.h>
#include <string.h>

#include "sfinx.h"

// Keypair {{{
//
// The secret is the seed, the public key is derived on demand
//   init sets the default hash, free releases both halves

void sfinx_key_init(sfinx_key *key) {
  if (!key) return;
  memset(key, 0, sizeof(*key));
  key->hash = SFINX_HASH_DEFAULT;
}

void sfinx_key_free(sfinx_key *key) {
  if (!key) return;
  free(key->seed);
  free(key->pub);
  memset(key, 0, sizeof(*key));
}

sfinx_status sfinx_key_derive(sfinx_key *key) {
  size_t       len;
  uint8_t     *pub;
  sfinx_status status;

  if (!key) {
    return SFINX_ERR_ARGS;
  }
  if (key->pub) {
    return SFINX_OK;
  }
  if (!key->seed) {
    return SFINX_ERR_ARGS;
  }
  len = sfinx_hash_len(key->hash);
  if (len == 0) {
    return SFINX_ERR_ARGS;
  }
  pub = malloc(len);
  if (!pub) {
    return SFINX_ERR_NOSPACE;
  }
  status = sfinx_tree_public_key(key->hash, key->seed, key->seed_len, pub, len, NULL);
  if (status != SFINX_OK) {
    free(pub);
    return status;
  }
  key->pub     = pub;
  key->pub_len = len;
  return SFINX_OK;
}
// }}}

// Registry {{{
//
// Formats prepend themselves on load, so the newest wins ties in search

static sfinx_format *sfinx_formats = NULL;

void sfinx_format_register(sfinx_format *format) {
  if (!format) return;
  format->next  = sfinx_formats;
  sfinx_formats = format;
}

const sfinx_format *sfinx_format_find(const char *name) {
  const sfinx_format *fmt;
  if (!name) return NULL;
  for (fmt = sfinx_formats; fmt; fmt = fmt->next) {
    if (fmt->name && strcmp(fmt->name, name) == 0) {
      return fmt;
    }
  }
  return NULL;
}

static const sfinx_format *sfinx_format_detect(const uint8_t *data, size_t len) {
  const sfinx_format *fmt;
  for (fmt = sfinx_formats; fmt; fmt = fmt->next) {
    if (fmt->detect && fmt->detect(data, len)) {
      return fmt;
    }
  }
  return NULL;
}
// }}}

// Dispatch {{{
//
// Decode mallocs into the key, encode writes into the caller buffer

sfinx_status sfinx_key_decode(const uint8_t *data, size_t len, const char *format, sfinx_key *out) {
  const sfinx_format *fmt;
  sfinx_status        status;

  if (!data || !out) {
    return SFINX_ERR_ARGS;
  }
  fmt = format ? sfinx_format_find(format) : sfinx_format_detect(data, len);
  if (!fmt || !fmt->decode) {
    return SFINX_ERR_FORMAT;
  }
  sfinx_key_init(out);
  status = fmt->decode(data, len, out);
  if (status != SFINX_OK) {
    sfinx_key_free(out);
  }
  return status;
}

size_t sfinx_key_encode_len(const sfinx_key *key, const char *format) {
  const sfinx_format *fmt;
  if (!key || !format) {
    return 0;
  }
  fmt = sfinx_format_find(format);
  if (!fmt || !fmt->encode_len) {
    return 0;
  }
  return fmt->encode_len(key);
}

sfinx_status sfinx_key_encode(const sfinx_key *key, const char *format, uint8_t *out, size_t cap, size_t *len_out) {
  const sfinx_format *fmt;
  if (!key || !format || !out) {
    return SFINX_ERR_ARGS;
  }
  fmt = sfinx_format_find(format);
  if (!fmt || !fmt->encode) {
    return SFINX_ERR_ARGS;
  }
  return fmt->encode(key, out, cap, len_out);
}
// }}}

// vim:fdm=marker:fdl=0
