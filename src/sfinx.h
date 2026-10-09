#ifndef __SFINX_H__
#define __SFINX_H__

#include <stddef.h>
#include <stdint.h>

// Hash sizes {{{
//
// SHA3 digest size in bits, L is the byte size
//   224 -> 28, 256 -> 32, 384 -> 48, 512 -> 64

#define SFINX_HASH_DEFAULT SFINX_HASH_256
#define SFINX_HASH_LEN_MAX 64

typedef enum {
  SFINX_HASH_224 = 224,
  SFINX_HASH_256 = 256,
  SFINX_HASH_384 = 384,
  SFINX_HASH_512 = 512
} sfinx_hash;

size_t sfinx_hash_len(sfinx_hash hash);
// }}}

#endif  // __SFINX_H__

// vim:fdm=marker:fdl=0
