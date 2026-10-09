#include "sfinx.h"

#include <coruus/keccak-tiny.h>
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
//   preimage = SHAKE256(seed), c * L bytes, c elements of L bytes
//   digits   = the value bytes, then 2 checksum bytes of 255 - value[i]
//   pubkey   = H of every element chained w times
//   proof    = every element chained d[i] times
//   verify   = chain every proof element w - d[i] times, then the pubkey hash

#define SFINX_WOTS_BYTES_MAX  ((SFINX_HASH_LEN_MAX + 2) * SFINX_HASH_LEN_MAX)
#define SFINX_WOTS_DIGITS_MAX (SFINX_HASH_LEN_MAX + 2)

static inline void _sfinx_wots_preimage(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *out) {
  size_t len = sfinx_hash_len(hash);
  _sfinx_shake256(seed, seed_len, out, (len + 2) * len);
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

static inline void _sfinx_wots_pubkey(sfinx_hash hash, const uint8_t *seed, size_t seed_len, uint8_t *pubkey_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t ends[SFINX_WOTS_BYTES_MAX];
  _sfinx_wots_preimage(hash, seed, seed_len, ends);
  for (size_t i = 0; i < len + 2; i++) {
    _sfinx_wots_chain(hash, ends + i * len, 256);
  }
  _sfinx_hash(hash, ends, (len + 2) * len, pubkey_out);
}

static inline void _sfinx_wots_proof(sfinx_hash hash, const uint8_t *seed, size_t seed_len, const uint8_t *value,
                                     uint8_t *proof_out) {
  size_t  len = sfinx_hash_len(hash);
  uint8_t digits[SFINX_WOTS_DIGITS_MAX];
  _sfinx_wots_preimage(hash, seed, seed_len, proof_out);
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

// vim:fdm=marker:fdl=0
