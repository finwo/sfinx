#include "sfinx.h"

#include <coruus/keccak-tiny.h>

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

// vim:fdm=marker:fdl=0
