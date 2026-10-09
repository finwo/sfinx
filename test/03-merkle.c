#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

static void check_u8(uint8_t got, uint8_t want, const char *what) {
  tap(got == want, what, "got 0x%02x, want 0x%02x", got, want);
}

int main(void) {
  static uint8_t tree[9][256][SFINX_HASH_LEN_MAX];
  static uint8_t auth[8][SFINX_HASH_LEN_MAX];
  uint8_t        manual[2 + SFINX_PATH_LEN_MAX + 2 * SFINX_HASH_LEN_MAX];
  uint8_t        prefix[4] = {0xde, 0xad, 0xbe, 0xef};
  uint8_t        parent[SFINX_HASH_LEN_MAX];
  uint8_t        other[SFINX_HASH_LEN_MAX];
  uint8_t        node[SFINX_HASH_LEN_MAX];
  uint8_t        tmp[SFINX_HASH_LEN_MAX];
  size_t         len = sfinx_hash_len(SFINX_HASH_256);
  size_t         idx = 0x5a;
  size_t         pos;

  tap_begin("sfinx Merkle");

  check_u8(_sfinx_node_mask(0, 0xff), 0x00, "mask depth 0");
  check_u8(_sfinx_node_mask(1, 0x80), 0x80, "mask depth 1, right");
  check_u8(_sfinx_node_mask(1, 0x7f), 0x00, "mask depth 1, left");
  check_u8(_sfinx_node_mask(6, 0x96), 0x94, "mask depth 6");
  check_u8(_sfinx_node_mask(7, 0xff), 0xfe, "mask depth 7");
  check_u8(_sfinx_node_mask(8, 0xab), 0xab, "mask depth 8");

  for (size_t i = 0; i < SFINX_HASH_LEN_MAX; i++) {
    tree[8][0][i] = (uint8_t)i;
    tree[8][1][i] = (uint8_t)(255 - i);
  }

  manual[0] = 3;
  manual[1] = 0x28;
  memcpy(manual + 2, prefix, 4);
  memcpy(manual + 6, tree[8][0], len);
  memcpy(manual + 6 + len, tree[8][1], len);
  _sfinx_hash(SFINX_HASH_256, manual, 2 + 4 + 2 * len, other);
  _sfinx_merkle_parent(SFINX_HASH_256, 3, 0x28, prefix, 4, tree[8][0], tree[8][1], parent);
  tap(memcmp(parent, other, len) == 0, "parent matches manual assembly", "parent differs");

  _sfinx_merkle_parent(SFINX_HASH_256, 4, 0x28, prefix, 4, tree[8][0], tree[8][1], tmp);
  tap(memcmp(parent, tmp, len) != 0, "bitlen changes the parent", "parents match");
  _sfinx_merkle_parent(SFINX_HASH_256, 3, 0x29, prefix, 4, tree[8][0], tree[8][1], tmp);
  tap(memcmp(parent, tmp, len) != 0, "mask changes the parent", "parents match");
  _sfinx_merkle_parent(SFINX_HASH_256, 3, 0x28, prefix, 3, tree[8][0], tree[8][1], tmp);
  tap(memcmp(parent, tmp, len) != 0, "prefix changes the parent", "parents match");
  _sfinx_merkle_parent(SFINX_HASH_256, 3, 0x28, prefix, 4, tree[8][1], tree[8][0], tmp);
  tap(memcmp(parent, tmp, len) != 0, "child order changes the parent", "parents match");

  for (size_t i = 0; i < 256; i++) {
    uint8_t leaf = (uint8_t)i;
    _sfinx_hash(SFINX_HASH_256, &leaf, 1, tree[8][i]);
  }

  for (size_t d = 8; d-- > 0;) {
    size_t n = (size_t)1 << d;
    for (size_t j = 0; j < n; j++) {
      _sfinx_merkle_parent(SFINX_HASH_256, (uint8_t)d, _sfinx_node_mask((uint8_t)d, (uint8_t)(j << (8 - d))), NULL, 0,
                           tree[d + 1][2 * j], tree[d + 1][2 * j + 1], tree[d][j]);
    }
  }

  pos = idx;
  for (size_t k = 0; k < 8; k++) {
    memcpy(auth[k], tree[8 - k][pos ^ 1], len);
    pos >>= 1;
  }

  pos = idx;
  memcpy(node, tree[8][idx], len);
  for (size_t k = 0; k < 8; k++) {
    uint8_t pd = (uint8_t)(7 - k);
    uint8_t pi = (uint8_t)((pos >> 1) << (8 - pd));
    if (pos & 1) {
      _sfinx_merkle_parent(SFINX_HASH_256, pd, _sfinx_node_mask(pd, pi), NULL, 0, auth[k], node, tmp);
    } else {
      _sfinx_merkle_parent(SFINX_HASH_256, pd, _sfinx_node_mask(pd, pi), NULL, 0, node, auth[k], tmp);
    }
    memcpy(node, tmp, len);
    pos >>= 1;
  }
  tap(memcmp(node, tree[0][0], len) == 0, "auth path rebuilds the root", "root differs");

  return tap_plan();
}
