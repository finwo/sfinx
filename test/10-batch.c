// Forces the pre-image batch to chunk, so the multi-chunk path is exercised
#define SFINX_BATCH_KEY_BUDGET 260u

#include <string.h>

#include "_tap.c"
#include "ref/sfinx_ref.c"
#include "src/sfinx.c"

int main(void) {
  static const uint8_t seed[]   = "sfinx batch chunk seed";
  static const uint8_t prefix[] = {0x11, 0x22, 0x33};
  static const int     bits[]   = {224, 512};
  size_t               seed_len = sizeof(seed) - 1;

  // key_len is 22 + 3 + 1 = 26, so the 260 budget makes chunk 10, not a lane multiple
  tap_begin("sfinx batch chunking");

  for (size_t s = 0; s < sizeof(bits) / sizeof(bits[0]); s++) {
    int        bit  = bits[s];
    sfinx_hash hash = (sfinx_hash)bit;
    size_t     len  = sfinx_hash_len(hash);
    uint8_t    lib_root[SFINX_HASH_LEN_MAX];
    uint8_t    ref_root[SFINX_HASH_LEN_MAX];
    uint8_t    lib_auth[8 * SFINX_HASH_LEN_MAX];
    uint8_t    ref_auth[8 * SFINX_HASH_LEN_MAX];
    char       label[64];

    tap(_sfinx_subtree_build(NULL, hash, seed, seed_len, prefix, sizeof(prefix), 0x5a, lib_root, lib_auth) != 0,
        "chunked subtree builds", "build failed");
    ref_subtree(bit, seed, seed_len, prefix, sizeof(prefix), 0x5a, ref_root, ref_auth);

    snprintf(label, sizeof(label), "L%zu chunked root matches reference", len);
    tap(memcmp(lib_root, ref_root, len) == 0, label, "root differs");
    snprintf(label, sizeof(label), "L%zu chunked auth matches reference", len);
    tap(memcmp(lib_auth, ref_auth, 8 * len) == 0, label, "auth differs");
  }

  return tap_plan();
}
