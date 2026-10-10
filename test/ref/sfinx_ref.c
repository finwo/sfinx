// Reference signer {{{
//
// Independent re-derivation of the sfinx scheme from PLAN.md
//   shares only the keccak-fast primitive with src/sfinx.c
//   a second code path, not a second language, so it checks the scheme logic and
//   the byte layout, not the hash (the hash is anchored by test_openssl.sh)
//   nothing here is production code, all symbols are static and prefixed ref_

#include <finwo/keccak-fast.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define REF_LEN_MAX    64
#define REF_DIGITS_MAX (REF_LEN_MAX + 2)
#define REF_WOTS_MAX   ((REF_LEN_MAX + 2) * REF_LEN_MAX)
#define REF_LEAVES_MAX (256 * REF_LEN_MAX)
#define REF_KEY_MAX    1024
#define REF_PARENT_MAX (2 + 256 + 2 * REF_LEN_MAX)

static size_t ref_len(int bits) {
  switch (bits) {
    case 224: return 28;
    case 256: return 32;
    case 384: return 48;
    case 512: return 64;
  }
  return 0;
}

static void ref_sha3(int bits, const uint8_t *in, size_t in_len, uint8_t *out) {
  switch (bits) {
    case 224: kf_sha3_224(out, 28, in, in_len); break;
    case 256: kf_sha3_256(out, 32, in, in_len); break;
    case 384: kf_sha3_384(out, 48, in, in_len); break;
    case 512: kf_sha3_512(out, 64, in, in_len); break;
  }
}

static void ref_shake(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  kf_shake256(out, out_len, in, in_len);
}

static uint32_t ref_e4m4_decode(uint8_t byte) {
  uint8_t exponent = (uint8_t)(byte >> 4);
  uint8_t mantissa = (uint8_t)(byte & 0x0f);
  if (exponent == 0) {
    return mantissa;
  }
  return (uint32_t)(16 + mantissa) << (exponent - 1);
}

static int ref_e4m4_encode(uint32_t value, uint8_t *out) {
  // Brute force the small field rather than the library's shift loop
  for (uint32_t exponent = 0; exponent < 16; exponent++) {
    for (uint32_t mantissa = 0; mantissa < 16; mantissa++) {
      uint32_t candidate = exponent == 0 ? mantissa : (16 + mantissa) << (exponent - 1);
      if (candidate == value) {
        *out = (uint8_t)((exponent << 4) | mantissa);
        return 1;
      }
    }
  }
  return 0;
}

static uint8_t ref_mask(uint8_t bitlen, uint8_t index) {
  // Keep the top bitlen bits with an explicit bit walk
  uint8_t out = 0;
  for (uint8_t i = 0; i < bitlen; i++) {
    uint8_t bit = (uint8_t)(1u << (7 - i));
    if (index & bit) {
      out |= bit;
    }
  }
  return out;
}

static void ref_parent(int bits, uint8_t bitlen, uint8_t mask, const uint8_t *prefix, size_t prefix_len,
                       const uint8_t *left, const uint8_t *right, uint8_t *out) {
  size_t  len = ref_len(bits);
  uint8_t buf[REF_PARENT_MAX];
  size_t  at = 0;
  if (prefix_len > 256) {
    return;
  }
  buf[at++] = bitlen;
  buf[at++] = mask;
  for (size_t i = 0; i < prefix_len; i++) {
    buf[at++] = prefix[i];
  }
  for (size_t i = 0; i < len; i++) {
    buf[at++] = left[i];
  }
  for (size_t i = 0; i < len; i++) {
    buf[at++] = right[i];
  }
  ref_sha3(bits, buf, at, out);
}

static void ref_pre(int bits, const uint8_t *key, size_t key_len, uint8_t *out) {
  size_t len = ref_len(bits);
  ref_shake(key, key_len, out, (len + 2) * len);
}

static void ref_digits(int bits, const uint8_t *value, uint8_t *out) {
  size_t   len      = ref_len(bits);
  uint32_t checksum = 0;
  for (size_t i = 0; i < len; i++) {
    out[i] = value[i];
    checksum += (uint32_t)(255 - value[i]);
  }
  out[len]     = (uint8_t)((checksum >> 8) & 0xff);
  out[len + 1] = (uint8_t)(checksum & 0xff);
}

static void ref_chain(int bits, uint8_t *node, uint32_t steps) {
  size_t  len = ref_len(bits);
  uint8_t next[REF_LEN_MAX];
  for (uint32_t i = 0; i < steps; i++) {
    ref_sha3(bits, node, len, next);
    memcpy(node, next, len);
  }
}

static void ref_pub(int bits, const uint8_t *key, size_t key_len, uint8_t *out) {
  size_t  len = ref_len(bits);
  uint8_t ends[REF_WOTS_MAX];
  ref_pre(bits, key, key_len, ends);
  for (size_t i = 0; i < len + 2; i++) {
    ref_chain(bits, ends + i * len, 256);
  }
  ref_sha3(bits, ends, (len + 2) * len, out);
}

static void ref_wots_sign(int bits, const uint8_t *key, size_t key_len, const uint8_t *value, uint8_t *proof) {
  size_t  len = ref_len(bits);
  uint8_t digits[REF_DIGITS_MAX];
  ref_pre(bits, key, key_len, proof);
  ref_digits(bits, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    ref_chain(bits, proof + i * len, digits[i]);
  }
}

static void ref_wots_rebuild(int bits, const uint8_t *value, const uint8_t *proof, uint8_t *out) {
  size_t  len = ref_len(bits);
  uint8_t digits[REF_DIGITS_MAX];
  uint8_t ends[REF_WOTS_MAX];
  ref_digits(bits, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    memcpy(ends + i * len, proof + i * len, len);
    ref_chain(bits, ends + i * len, 256 - digits[i]);
  }
  ref_sha3(bits, ends, (len + 2) * len, out);
}

static void ref_subtree(int bits, const uint8_t *seed, size_t seed_len, const uint8_t *prefix, size_t prefix_len,
                        uint8_t leaf_index, uint8_t *root_out, uint8_t *auth_out) {
  size_t  len     = ref_len(bits);
  size_t  key_len = seed_len + prefix_len + 1;
  size_t  pos     = leaf_index;
  uint8_t leaves[REF_LEAVES_MAX];
  uint8_t key[REF_KEY_MAX];

  if (key_len > REF_KEY_MAX) {
    return;
  }
  for (size_t i = 0; i < seed_len; i++) {
    key[i] = seed[i];
  }
  for (size_t i = 0; i < prefix_len; i++) {
    key[seed_len + i] = prefix[i];
  }
  for (uint32_t i = 0; i < 256; i++) {
    key[key_len - 1] = (uint8_t)i;
    ref_pub(bits, key, key_len, leaves + (size_t)i * len);
  }
  for (uint8_t depth = 0; depth < 8; depth++) {
    uint8_t bitlen = (uint8_t)(7 - depth);
    size_t  pairs  = (size_t)1 << (7 - depth);
    if (auth_out) {
      size_t sibling = pos ^ 1u;
      for (size_t i = 0; i < len; i++) {
        auth_out[(size_t)depth * len + i] = leaves[sibling * len + i];
      }
    }
    for (size_t j = 0; j < pairs; j++) {
      uint8_t mask = ref_mask(bitlen, (uint8_t)(j << (8 - bitlen)));
      ref_parent(bits, bitlen, mask, prefix, prefix_len, leaves + (2 * j) * len, leaves + (2 * j + 1) * len,
                 leaves + j * len);
    }
    pos >>= 1;
  }
  for (size_t i = 0; i < len; i++) {
    root_out[i] = leaves[i];
  }
}

static size_t ref_signature_len(int bits, size_t path_len) {
  size_t len = ref_len(bits);
  if (len == 0) {
    return 0;
  }
  if (path_len == 0) {
    return 2 + (len + 2) * len;
  }
  return 2 + path_len + path_len * (len + 10) * len;
}

static void ref_single_pub(int bits, const uint8_t *seed, size_t seed_len, uint8_t *out) {
  ref_pub(bits, seed, seed_len, out);
}

static void ref_single_sign(int bits, const uint8_t *seed, size_t seed_len, const uint8_t *msg, size_t msg_len,
                            uint8_t *sig) {
  size_t  len = ref_len(bits);
  uint8_t org[REF_LEN_MAX];
  ref_sha3(bits, msg, msg_len, org);
  ref_e4m4_encode(0, sig);
  ref_e4m4_encode((uint32_t)len, sig + 1);
  ref_wots_sign(bits, seed, seed_len, org, sig + 2);
}

static void ref_tree_pub(int bits, const uint8_t *seed, size_t seed_len, uint8_t *out) {
  ref_subtree(bits, seed, seed_len, NULL, 0, 0, out, NULL);
}

static void ref_tree_sign(int bits, const uint8_t *seed, size_t seed_len, const uint8_t *path, size_t path_len,
                          const uint8_t *msg, size_t msg_len, uint8_t *sig) {
  size_t   len = ref_len(bits);
  size_t   c   = len + 2;
  size_t   at  = 0;
  uint8_t  value[REF_LEN_MAX];
  uint8_t  root[REF_LEN_MAX];
  uint8_t  auth[8 * REF_LEN_MAX];
  uint8_t  key[REF_KEY_MAX];
  uint8_t *joined = malloc(path_len + msg_len);

  if (!joined || seed_len + path_len + 1 > REF_KEY_MAX) {
    free(joined);
    return;
  }
  memcpy(joined, path, path_len);
  memcpy(joined + path_len, msg, msg_len);
  ref_sha3(bits, joined, path_len + msg_len, value);
  free(joined);

  ref_e4m4_encode((uint32_t)path_len, sig);
  at = 1;
  for (size_t i = 0; i < path_len; i++) {
    sig[at++] = path[i];
  }
  ref_e4m4_encode((uint32_t)len, sig + at);
  at += 1;

  for (size_t i = 0; i < seed_len; i++) {
    key[i] = seed[i];
  }
  for (size_t i = 0; i < path_len; i++) {
    key[seed_len + i] = path[i];
  }

  for (size_t k = path_len; k >= 1; k--) {
    ref_subtree(bits, seed, seed_len, path, k - 1, path[k - 1], root, auth);
    ref_wots_sign(bits, key, seed_len + k, value, sig + at);
    at += c * len;
    for (size_t i = 0; i < 8 * len; i++) {
      sig[at++] = auth[i];
    }
    for (size_t i = 0; i < len; i++) {
      value[i] = root[i];
    }
  }
}

static int ref_verify(const uint8_t *pub, size_t pub_len, const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                      size_t sig_len) {
  size_t   path_len;
  size_t   len;
  size_t   c;
  size_t   at;
  size_t   pos;
  int      bits;
  uint8_t  value[REF_LEN_MAX];
  uint8_t  leaf[REF_LEN_MAX];
  uint8_t  root[REF_LEN_MAX];
  uint8_t *joined;

  if (sig_len < 2) {
    return 0;
  }
  path_len = ref_e4m4_decode(sig[0]);
  at       = 1 + path_len;
  if (at + 1 > sig_len) {
    return 0;
  }
  len = ref_e4m4_decode(sig[at]);
  if (len == 28) {
    bits = 224;
  } else if (len == 32) {
    bits = 256;
  } else if (len == 48) {
    bits = 384;
  } else if (len == 64) {
    bits = 512;
  } else {
    return 0;
  }
  if (len != pub_len || sig_len != ref_signature_len(bits, path_len)) {
    return 0;
  }
  c  = len + 2;
  at = 2 + path_len;

  if (path_len == 0) {
    ref_sha3(bits, msg, msg_len, value);
    ref_wots_rebuild(bits, value, sig + at, leaf);
    return memcmp(leaf, pub, len) == 0;
  }

  joined = malloc(path_len + msg_len);
  if (!joined) {
    return 0;
  }
  memcpy(joined, sig + 1, path_len);
  memcpy(joined + path_len, msg, msg_len);
  ref_sha3(bits, joined, path_len + msg_len, value);
  free(joined);

  for (size_t k = path_len; k >= 1; k--) {
    ref_wots_rebuild(bits, value, sig + at, leaf);
    at += c * len;
    pos = sig[k];
    for (size_t i = 0; i < len; i++) {
      root[i] = leaf[i];
    }
    for (uint8_t depth = 0; depth < 8; depth++) {
      uint8_t        bitlen  = (uint8_t)(7 - depth);
      uint8_t        mask    = ref_mask(bitlen, (uint8_t)((pos >> 1) << (8 - bitlen)));
      const uint8_t *sibling = sig + at + (size_t)depth * len;
      uint8_t        tmp[REF_LEN_MAX];
      if (pos & 1) {
        ref_parent(bits, bitlen, mask, sig + 1, k - 1, sibling, root, tmp);
      } else {
        ref_parent(bits, bitlen, mask, sig + 1, k - 1, root, sibling, tmp);
      }
      memcpy(root, tmp, len);
      pos >>= 1;
    }
    at += 8 * len;
    if (k == 1) {
      return memcmp(root, pub, len) == 0;
    }
    memcpy(value, root, len);
  }
  return 0;
}
// }}}

// vim:fdm=marker:fdl=0
