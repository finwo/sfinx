#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

#define MSG     "sfinx tweak vector"
#define MSG_LEN (sizeof(MSG) - 1)

static void step(sfinx_hash hash, const uint8_t *kid, uint8_t index, uint8_t from, uint8_t *out) {
  uint8_t node[SFINX_HASH_LEN_MAX];
  for (size_t i = 0; i < sfinx_hash_len(hash); i++) {
    node[i] = (uint8_t)(i + 1);
  }
  _sfinx_wots_chain(hash, node, kid, index, from, 1);
  memcpy(out, node, sfinx_hash_len(hash));
}

static void kid_for(sfinx_hash hash, size_t path_len, const uint8_t *path, size_t k, uint8_t *out) {
  uint8_t suffix[SFINX_HASH_LEN_MAX];
  _sfinx_e4m4_encode((uint32_t)path_len, suffix);
  for (size_t i = 0; i < k; i++) {
    suffix[1 + i] = path[i];
  }
  _sfinx_kid(hash, suffix, k + 1, out);
}

static void roundtrip(sfinx_hash hash, size_t path_len, const char *label) {
  static const uint8_t seed[] = "sfinx tweak seed";
  uint8_t              path[32];
  uint8_t              pub[SFINX_HASH_LEN_MAX];
  uint8_t             *sig;
  size_t               seed_len = strlen((const char *)seed);
  size_t               n        = sfinx_signature_len(hash, path_len);
  size_t               got      = 0;
  char                 name[96];

  for (size_t i = 0; i < sizeof(path); i++) {
    path[i] = (uint8_t)(i * 3 + 1);
  }
  sig = malloc(n);
  if (!sig) {
    tap(0, label, "out of memory");
    return;
  }

  if (path_len == 0) {
    sfinx_single_public_key(hash, seed, seed_len, pub, sizeof(pub), &got);
    sfinx_single_sign(hash, seed, seed_len, (const uint8_t *)MSG, MSG_LEN, sig, n, NULL);
  } else {
    sfinx_tree_public_key(hash, seed, seed_len, path_len, pub, sizeof(pub), &got);
    sfinx_tree_sign(hash, seed, seed_len, path, path_len, (const uint8_t *)MSG, MSG_LEN, sig, n, NULL);
  }

  snprintf(name, sizeof(name), "%s verifies", label);
  tap(sfinx_verify(pub, got, (const uint8_t *)MSG, MSG_LEN, sig, n) == SFINX_OK, name, "verify failed");

  sig[n / 2] ^= 0x01;
  snprintf(name, sizeof(name), "%s rejects a tampered signature", label);
  tap(sfinx_verify(pub, got, (const uint8_t *)MSG, MSG_LEN, sig, n) != SFINX_OK, name, "verify passed");

  free(sig);
}

int main(void) {
  static const sfinx_hash hashes[] = {SFINX_HASH_224, SFINX_HASH_256, SFINX_HASH_384, SFINX_HASH_512};
  static const char      *sizes[]  = {"224", "256", "384", "512"};
  uint8_t                 kid[SFINX_HASH_LEN_MAX];
  uint8_t                 other[SFINX_HASH_LEN_MAX];
  uint8_t                 a[SFINX_HASH_LEN_MAX];
  uint8_t                 b[SFINX_HASH_LEN_MAX];
  uint8_t                 path1[] = {0x0a, 0x1b};
  uint8_t                 path2[] = {0x0a, 0x2c};
  size_t                  len     = sfinx_hash_len(SFINX_HASH_256);
  size_t                  k       = _sfinx_kid_len(SFINX_HASH_256);

  tap_begin("sfinx chain tweak");

  _sfinx_kid(SFINX_HASH_256, (const uint8_t *)"\x01\x0a", 2, kid);

  memcpy(other, kid, k);
  other[0] ^= 0x01;
  step(SFINX_HASH_256, kid, 3, 0, a);
  step(SFINX_HASH_256, other, 3, 0, b);
  tap(memcmp(a, b, len) != 0, "a different key id changes the step", "outputs match");

  step(SFINX_HASH_256, kid, 3, 0, a);
  step(SFINX_HASH_256, kid, 4, 0, b);
  tap(memcmp(a, b, len) != 0, "a different chain index changes the step", "outputs match");

  step(SFINX_HASH_256, kid, 3, 0, a);
  step(SFINX_HASH_256, kid, 3, 1, b);
  tap(memcmp(a, b, len) != 0, "a different step index changes the step", "outputs match");

  kid_for(SFINX_HASH_256, 2, path1, 2, a);
  kid_for(SFINX_HASH_256, 2, path2, 2, b);
  tap(memcmp(a, b, k) != 0, "different paths give different key ids", "key ids match");

  kid_for(SFINX_HASH_256, 2, path1, 1, a);
  kid_for(SFINX_HASH_256, 3, path1, 1, b);
  tap(memcmp(a, b, k) != 0, "the same path at a different N gives a different key id", "key ids match");

  for (size_t h = 0; h < 4; h++) {
    char label[64];
    for (size_t p = 0; p < 3; p++) {
      snprintf(label, sizeof(label), "L%s N%zu", sizes[h], p);
      roundtrip(hashes[h], p, label);
    }
  }
  roundtrip(SFINX_HASH_256, 32, "L256 N32");

  return tap_plan();
}
