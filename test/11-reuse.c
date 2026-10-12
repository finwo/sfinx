#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

#define MSG     "sfinx reuse regression"
#define MSG_LEN (sizeof(MSG) - 1)

// Without N in the key, an N=1 signature shares its layer-1 key with any longer one on the same path[0]

static void layer1_pubkey(const uint8_t *seed, size_t seed_len, size_t path_len, uint8_t first, uint8_t *out) {
  uint8_t key[64];
  memcpy(key, seed, seed_len);
  _sfinx_e4m4_encode((uint32_t)path_len, key + seed_len);
  key[seed_len + 1] = first;
  _sfinx_wots_pubkey(SFINX_HASH_256, key, seed_len + 2, out);
}

int main(void) {
  static const uint8_t seed[]  = "sfinx reuse seed";
  uint8_t              path1[] = {0x0a};
  uint8_t              path2[] = {0x0a, 0x1b};
  uint8_t              pub1[SFINX_HASH_LEN_MAX];
  uint8_t              pub2[SFINX_HASH_LEN_MAX];
  uint8_t              sig1[4096];
  uint8_t              sig2[4096];
  size_t               len      = sfinx_hash_len(SFINX_HASH_256);
  size_t               seed_len = strlen((const char *)seed);
  size_t               n1       = sfinx_signature_len(SFINX_HASH_256, 1);
  size_t               n2       = sfinx_signature_len(SFINX_HASH_256, 2);

  tap_begin("sfinx cross-length key reuse");

  layer1_pubkey(seed, seed_len, 1, path1[0], pub1);
  layer1_pubkey(seed, seed_len, 2, path2[0], pub2);
  tap(memcmp(pub1, pub2, len) != 0, "layer-1 key differs across path lengths", "one key serves both");

  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path1, 1, (const uint8_t *)MSG, MSG_LEN, sig1, n1, NULL) ==
          SFINX_OK,
      "N=1 signs", "sign failed");
  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path2, 2, (const uint8_t *)MSG, MSG_LEN, sig2, n2, NULL) ==
          SFINX_OK,
      "N=2 signs", "sign failed");

  tap(memcmp(sig1 + n1 - 8 * len, sig2 + n2 - 8 * len, 8 * len) != 0, "layer-1 auth paths differ across path lengths",
      "auth paths are identical");

  tap(memcmp(sig1 + 3, sig2 + n2 - (len + 10) * len, (len + 2) * len) != 0, "layer-1 proofs are not a reuse pair",
      "proofs come from one key");

  return tap_plan();
}
