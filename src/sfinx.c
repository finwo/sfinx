#include <stdint.h>

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

  uint32_t base = value;
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

// vim:fdm=marker:fdl=0
