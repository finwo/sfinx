#include "sfinx.h"

#include <coruus/keccak-tiny.h>
#include <stdlib.h>
#include <string.h>

// E4M4 {{{
//
// Log-ish number format, only positive
//   E=0: M
//   E>0: (16+M)<<(E-1)

static inline uint32_t _sfinx_e4m4_decode(uint8_t byte) {
  uint8_t exponent = (uint8_t)(byte >> 4);
  uint8_t mantissa = (uint8_t)(byte & 0x0f);
  if (exponent == 0) {
    return mantissa;
  }
  return (uint32_t)(16 + mantissa) << (exponent - 1);
}

static inline uint32_t _sfinx_e4m4_encode(uint32_t value, uint8_t *out) {
  if (value <= 15) {
    *out = (uint8_t)value;
    return 1;
  }

  uint32_t base  = value;
  uint32_t shift = 0;
  while (base > 31) {
    base >>= 1;
    if (++shift > 14) {
      return 0;
    }
  }
  if (base < 16 || (base << shift) != value) {
    return 0;
  }

  *out = (uint8_t)(((shift + 1) << 4) | (base - 16));
  return 1;
}
// }}}

// Hash backend {{{
//
// SHA3 for fixed-size hashing, SHAKE256 for the pre-image XOF
//   _sfinx_hash(hash, in, in_len, out)
//   _sfinx_shake256(in, in_len, out, out_len)

static inline void _sfinx_hash(sfinx_hash hash, const uint8_t *in, size_t in_len, uint8_t *out) {
  switch (hash) {
    case SFINX_HASH_224: sha3_224(out, 28, in, in_len); break;
    case SFINX_HASH_256: sha3_256(out, 32, in, in_len); break;
    case SFINX_HASH_384: sha3_384(out, 48, in, in_len); break;
    case SFINX_HASH_512: sha3_512(out, 64, in, in_len); break;
  }
}

static inline void _sfinx_shake256(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len) {
  shake256(out, out_len, in, in_len);
}

size_t sfinx_hash_len(sfinx_hash hash) {
  switch (hash) {
    case SFINX_HASH_224: return 28;
    case SFINX_HASH_256: return 32;
    case SFINX_HASH_384: return 48;
    case SFINX_HASH_512: return 64;
  }
  return 0;
}
// }}}

// WOTS {{{
//
// One WOTS key over an L-byte value, c = L + 2 chains of length 256
//   key      = seed for N = 0, seed | path for a tree leaf
//   preimage = SHAKE256(key), c * L bytes, c elements of L bytes
//   digits   = the value bytes, then 2 checksum bytes of 255 - value[i]
//   pubkey   = H of every element chained w times
//   proof    = every element chained d[i] times
//   verify   = chain every proof element w - d[i] times, then the pubkey hash

#define SFINX_WOTS_BYTES_MAX  ((SFINX_HASH_LEN_MAX + 2) * SFINX_HASH_LEN_MAX)
#define SFINX_WOTS_DIGITS_MAX (SFINX_HASH_LEN_MAX + 2)

static inline void _sfinx_wots_preimage(sfinx_hash hash, const uint8_t *key, size_t key_len, uint8_t *out) {
  size_t len = sfinx_hash_len(hash);
  _sfinx_shake256(key, key_len, out, (len + 2) * len);
}

static inline void _sfinx_wots_digits(sfinx_hash hash, const uint8_t *value, uint8_t *out) {
  size_t   len      = sfinx_hash_len(hash);
  uint32_t checksum = 0;
  for (size_t i = 0; i < len; i++) {
    out[i] = value[i];
    checksum += 255 - value[i];
  }
  out[len]     = (uint8_t)(checksum >> 8);
  out[len + 1] = (uint8_t)checksum;
}

static inline void _sfinx_wots_chain(sfinx_hash hash, uint8_t *node, uint32_t steps) {
  uint8_t next[SFINX_HASH_LEN_MAX];
  size_t  len = sfinx_hash_len(hash);
  for (uint32_t i = 0; i < steps; i++) {
    _sfinx_hash(hash, node, len, next);
    memcpy(node, next, len);
  }
}

static inline void _sfinx_wots_pubkey(sfinx_hash hash, const uint8_t *key, size_t key_len, uint8_t *pubkey_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t ends[SFINX_WOTS_BYTES_MAX];
  _sfinx_wots_preimage(hash, key, key_len, ends);
  for (size_t i = 0; i < len + 2; i++) {
    _sfinx_wots_chain(hash, ends + i * len, 256);
  }
  _sfinx_hash(hash, ends, (len + 2) * len, pubkey_out);
}

static inline void _sfinx_wots_proof(sfinx_hash hash, const uint8_t *key, size_t key_len, const uint8_t *value,
                                     uint8_t *proof_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t digits[SFINX_WOTS_DIGITS_MAX];
  _sfinx_wots_preimage(hash, key, key_len, proof_out);
  _sfinx_wots_digits(hash, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    _sfinx_wots_chain(hash, proof_out + i * len, digits[i]);
  }
}

static inline int _sfinx_wots_verify(sfinx_hash hash, const uint8_t *pubkey, const uint8_t *value,
                                     const uint8_t *proof) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t digits[SFINX_WOTS_DIGITS_MAX];
  uint8_t ends[SFINX_WOTS_BYTES_MAX];
  uint8_t want[SFINX_HASH_LEN_MAX];
  uint8_t node[SFINX_HASH_LEN_MAX];
  _sfinx_wots_digits(hash, value, digits);
  for (size_t i = 0; i < len + 2; i++) {
    memcpy(node, proof + i * len, len);
    _sfinx_wots_chain(hash, node, 256 - digits[i]);
    memcpy(ends + i * len, node, len);
  }
  _sfinx_hash(hash, ends, (len + 2) * len, want);
  return memcmp(want, pubkey, len) == 0;
}
// }}}

// Merkle {{{
//
// Position-keyed parent hash of a binary subtree of height 8, 256 leaves
//   parent = H(bitlen | mask | prefix | left | right)
//   bitlen = the sub-byte depth d, mask = index & (0xFF << (8 - d)), low bits dropped

static inline uint8_t _sfinx_node_mask(uint8_t bitlen, uint8_t index) {
  return (uint8_t)(index & (0xFFu << (8 - bitlen)));
}

static inline void _sfinx_merkle_parent(sfinx_hash hash, uint8_t bitlen, uint8_t mask, const uint8_t *prefix,
                                        size_t prefix_len, const uint8_t *left, const uint8_t *right, uint8_t *out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t buf[2 + SFINX_PATH_LEN_MAX + 2 * SFINX_HASH_LEN_MAX];
  size_t  at = 0;
  buf[at++]  = bitlen;
  buf[at++]  = mask;
  if (prefix_len > 0) {
    memcpy(buf + at, prefix, prefix_len);
    at += prefix_len;
  }
  memcpy(buf + at, left, len);
  at += len;
  memcpy(buf + at, right, len);
  at += len;
  _sfinx_hash(hash, buf, at, out);
}
// }}}

// Subtree {{{
//
// One subtree of height 8, 256 WOTS leaves folded into a root
//   leaf i is keyed by SHAKE256(seed | prefix | i)
//   parent = H(bitlen | mask | prefix | left | right), the mask from the leaf index
//   build returns the root, and for one leaf the 8 auth siblings, deepest first
//   verify folds a leaf and its siblings back up to the root

static inline int _sfinx_subtree_build(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *prefix,
                                       size_t prefix_len, uint8_t leaf_index, uint8_t *root_out, uint8_t *auth_out) {
  size_t   len   = sfinx_hash_len(hash);
  size_t   count = 256;
  size_t   pos   = leaf_index;
  uint8_t  nodes[256 * SFINX_HASH_LEN_MAX];
  uint8_t *key = malloc(seed_len + prefix_len + 1);
  if (!key) {
    return 0;
  }
  memcpy(key, seed, seed_len);
  if (prefix_len > 0) {
    memcpy(key + seed_len, prefix, prefix_len);
  }
  for (size_t i = 0; i < 256; i++) {
    key[seed_len + prefix_len] = (uint8_t)i;
    _sfinx_wots_pubkey(hash, key, seed_len + prefix_len + 1, nodes + i * len);
  }
  free(key);
  for (size_t bitlen = 8; bitlen-- > 0;) {
    if (auth_out) {
      memcpy(auth_out + (7 - bitlen) * len, nodes + (pos ^ 1) * len, len);
    }
    count /= 2;
    for (size_t j = 0; j < count; j++) {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, _sfinx_node_mask((uint8_t)bitlen, (uint8_t)(j << (8 - bitlen))),
                           prefix, prefix_len, nodes + (2 * j) * len, nodes + (2 * j + 1) * len, nodes + j * len);
    }
    pos >>= 1;
  }
  memcpy(root_out, nodes, len);
  return 1;
}

static inline void _sfinx_subtree_verify(sfinx_hash hash, const uint8_t *prefix, size_t prefix_len, const uint8_t *leaf,
                                         uint8_t leaf_index, const uint8_t *auth, uint8_t *root_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t node[SFINX_HASH_LEN_MAX];
  uint8_t tmp[SFINX_HASH_LEN_MAX];
  size_t  pos = leaf_index;
  memcpy(node, leaf, len);
  for (size_t bitlen = 8; bitlen-- > 0;) {
    uint8_t        mask = _sfinx_node_mask((uint8_t)bitlen, (uint8_t)((pos >> 1) << (8 - bitlen)));
    const uint8_t *sib  = auth + (7 - bitlen) * len;
    if (pos & 1) {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, mask, prefix, prefix_len, sib, node, tmp);
    } else {
      _sfinx_merkle_parent(hash, (uint8_t)bitlen, mask, prefix, prefix_len, node, sib, tmp);
    }
    memcpy(node, tmp, len);
    pos >>= 1;
  }
  memcpy(root_out, node, len);
}
// }}}

// vim:fdm=marker:fdl=0
