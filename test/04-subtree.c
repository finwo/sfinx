#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

int main(void) {
  static const uint8_t seed[]     = "sfinx subtree seed";
  uint8_t              prefix[3]  = {0x11, 0x22, 0x33};
  uint8_t              prefix2[3] = {0x11, 0x22, 0x34};
  uint8_t              root[SFINX_HASH_LEN_MAX];
  uint8_t              root2[SFINX_HASH_LEN_MAX];
  uint8_t              auth[8 * SFINX_HASH_LEN_MAX];
  uint8_t              leaf[SFINX_HASH_LEN_MAX];
  uint8_t              leaf2[SFINX_HASH_LEN_MAX];
  uint8_t              built[SFINX_HASH_LEN_MAX];
  uint8_t              key[32];
  uint8_t              nodes[256 * SFINX_HASH_LEN_MAX];
  uint8_t              idx      = 0x5a;
  size_t               len      = sfinx_hash_len(SFINX_HASH_256);
  size_t               seed_len = strlen((const char *)seed);
  size_t               count;

  tap_begin("sfinx subtree");

  tap(_sfinx_subtree_build(SFINX_HASH_256, seed, seed_len, prefix, 3, idx, root, auth), "subtree builds",
      "build failed");

  memcpy(key, seed, seed_len);
  memcpy(key + seed_len, prefix, 3);
  key[seed_len + 3] = idx;
  _sfinx_wots_pubkey(SFINX_HASH_256, key, seed_len + 4, leaf);
  _sfinx_subtree_verify(SFINX_HASH_256, prefix, 3, leaf, idx, auth, built);
  tap(memcmp(built, root, len) == 0, "auth path rebuilds the subtree root", "root differs");

  auth[5] ^= 0x01;
  _sfinx_subtree_verify(SFINX_HASH_256, prefix, 3, leaf, idx, auth, built);
  tap(memcmp(built, root, len) != 0, "tampered auth fails", "root matched");
  auth[5] ^= 0x01;

  memcpy(leaf2, leaf, len);
  leaf2[0] ^= 0x01;
  _sfinx_subtree_verify(SFINX_HASH_256, prefix, 3, leaf2, idx, auth, built);
  tap(memcmp(built, root, len) != 0, "tampered leaf fails", "root matched");

  tap(_sfinx_subtree_build(SFINX_HASH_256, seed, seed_len, prefix2, 3, idx, root2, NULL), "second subtree builds",
      "build failed");
  tap(memcmp(root, root2, len) != 0, "prefix changes the subtree root", "roots match");

  for (size_t i = 0; i < 256; i++) {
    memcpy(key, seed, seed_len);
    memcpy(key + seed_len, prefix, 3);
    key[seed_len + 3] = (uint8_t)i;
    _sfinx_wots_pubkey(SFINX_HASH_256, key, seed_len + 4, nodes + i * len);
  }
  count = 256;
  for (size_t bitlen = 8; bitlen-- > 0;) {
    count /= 2;
    for (size_t j = 0; j < count; j++) {
      _sfinx_merkle_parent(SFINX_HASH_256, (uint8_t)bitlen,
                           _sfinx_node_mask((uint8_t)bitlen, (uint8_t)(j << (8 - bitlen))), prefix, 3,
                           nodes + (2 * j) * len, nodes + (2 * j + 1) * len, nodes + j * len);
    }
  }
  tap(memcmp(nodes, root, len) == 0, "manual fold matches the builder", "roots differ");

  return tap_plan();
}
