#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

#define MSG     "sfinx reuse regression"
#define MSG_LEN (sizeof(MSG) - 1)

// Two WOTS signatures from one key sit on the same chains, so one walks forward onto the other
static size_t chains_linked(sfinx_hash hash, const uint8_t *a, const uint8_t *b, size_t len, size_t count) {
  uint8_t walk[SFINX_HASH_LEN_MAX];
  size_t  linked = 0;
  for (size_t i = 0; i < count; i++) {
    for (int dir = 0; dir < 2; dir++) {
      const uint8_t *from = dir ? b : a;
      const uint8_t *to   = dir ? a : b;
      memcpy(walk, from + i * len, len);
      for (size_t step = 0; step < 256; step++) {
        if (memcmp(walk, to + i * len, len) == 0) {
          linked++;
          dir = 2;
          break;
        }
        _sfinx_hash(hash, walk, len, walk);
      }
    }
  }
  return linked;
}

int main(void) {
  static const uint8_t seed[]  = "sfinx reuse seed";
  uint8_t              path1[] = {0x0a};
  uint8_t              path2[] = {0x0a, 0x1b};
  uint8_t              sig1[4096];
  uint8_t              sig2[4096];
  size_t               len      = sfinx_hash_len(SFINX_HASH_256);
  size_t               seed_len = strlen((const char *)seed);
  size_t               n1       = sfinx_signature_len(SFINX_HASH_256, 1);
  size_t               n2       = sfinx_signature_len(SFINX_HASH_256, 2);
  size_t               linked;

  tap_begin("sfinx cross-length key reuse");

  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path1, 1, (const uint8_t *)MSG, MSG_LEN, sig1, n1, NULL) ==
          SFINX_OK,
      "N=1 signs", "sign failed");
  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path2, 2, (const uint8_t *)MSG, MSG_LEN, sig2, n2, NULL) ==
          SFINX_OK,
      "N=2 signs", "sign failed");

  tap(memcmp(sig1 + n1 - 8 * len, sig2 + n2 - 8 * len, 8 * len) != 0, "layer-1 auth paths differ across path lengths",
      "auth paths are identical");

  linked = chains_linked(SFINX_HASH_256, sig1 + 3, sig2 + n2 - (len + 10) * len, len, len + 2);
  tap(linked == 0, "layer-1 proofs do not chain onto each other", "%zu of %zu chains link", linked, len + 2);

  return tap_plan();
}
