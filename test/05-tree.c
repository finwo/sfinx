#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

#define SIG_MAX 8192

int main(void) {
  static const uint8_t seed[] = "sfinx tree seed";
  static const uint8_t msg[]  = "hello tree";
  uint8_t              single_pub[SFINX_HASH_LEN_MAX];
  uint8_t              tree_pub[SFINX_HASH_LEN_MAX];
  uint8_t              path1[1] = {0xa5};
  uint8_t              path2[2] = {0xa5, 0x3c};
  uint8_t              sig[SIG_MAX];
  uint8_t              sig2[SIG_MAX];
  size_t               len      = sfinx_hash_len(SFINX_HASH_256);
  size_t               seed_len = strlen((const char *)seed);
  size_t               msg_len  = strlen((const char *)msg);
  size_t               n0       = sfinx_signature_len(SFINX_HASH_256, 0);
  size_t               n1       = sfinx_signature_len(SFINX_HASH_256, 1);
  size_t               n2       = sfinx_signature_len(SFINX_HASH_256, 2);
  size_t               outlen;

  tap_begin("sfinx tree");

  tap(sfinx_single_public_key(SFINX_HASH_256, seed, seed_len, single_pub, len, &outlen) == SFINX_OK,
      "single pubkey builds", "build failed");
  tap(sfinx_single_sign(SFINX_HASH_256, seed, seed_len, msg, msg_len, sig, n0, &outlen) == SFINX_OK, "single signs",
      "sign failed");
  tap(sfinx_verify(single_pub, len, msg, msg_len, sig, n0) == SFINX_OK, "single verifies", "verify failed");
  sig[5] ^= 0x01;
  tap(sfinx_verify(single_pub, len, msg, msg_len, sig, n0) != SFINX_OK, "single tamper fails", "verify passed");

  tap(sfinx_tree_public_key(SFINX_HASH_256, seed, seed_len, tree_pub, len, &outlen) == SFINX_OK, "tree pubkey builds",
      "build failed");
  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path1, 1, msg, msg_len, sig, n1, &outlen) == SFINX_OK,
      "tree signs N=1", "sign failed");
  tap(sfinx_verify(tree_pub, len, msg, msg_len, sig, n1) == SFINX_OK, "tree verifies N=1", "verify failed");
  sig[n1 - 1] ^= 0x01;
  tap(sfinx_verify(tree_pub, len, msg, msg_len, sig, n1) != SFINX_OK, "tree tamper N=1 fails", "verify passed");

  tap(sfinx_tree_sign(SFINX_HASH_256, seed, seed_len, path2, 2, msg, msg_len, sig2, n2, &outlen) == SFINX_OK,
      "tree signs N=2", "sign failed");
  tap(sfinx_verify(tree_pub, len, msg, msg_len, sig2, n2) == SFINX_OK, "tree verifies N=2", "verify failed");
  tap(sfinx_verify(tree_pub, len, (const uint8_t *)"other", 5, sig2, n2) != SFINX_OK, "tree wrong message fails",
      "verify passed");

  tree_pub[0] ^= 0x01;
  tap(sfinx_verify(tree_pub, len, msg, msg_len, sig2, n2) != SFINX_OK, "tree wrong pubkey fails", "verify passed");
  tree_pub[0] ^= 0x01;

  return tap_plan();
}
