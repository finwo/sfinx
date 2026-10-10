// Prints signatures for a fixed seed, path, and message, so a -pthread build
// and a plain build can be diffed byte for byte

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "src/sfinx.c"

int main(void) {
  static const uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                   0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                   0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t path[3]  = {0x0a, 0x1b, 0x2c};
  static const char    msg[]    = "sfinx thread dump";
  static const int     bits[]   = {224, 256, 384, 512};
  size_t               msg_len  = sizeof(msg) - 1;

  for (size_t s = 0; s < sizeof(bits) / sizeof(bits[0]); s++) {
    for (size_t n = 1; n <= 3; n += 2) {
      uint8_t sig[32768];
      size_t  sig_len = 0;
      if (sfinx_tree_sign((sfinx_hash)bits[s], seed, sizeof(seed), path, n, (const uint8_t *)msg, msg_len, sig,
                          sizeof(sig), &sig_len) != SFINX_OK) {
        fprintf(stderr, "sign failed for L%d N%zu\n", bits[s], n);
        return 1;
      }
      printf("L=%d N=%zu ", bits[s], n);
      for (size_t i = 0; i < sig_len; i++) {
        printf("%02x", sig[i]);
      }
      printf("\n");
    }
  }
  return 0;
}
