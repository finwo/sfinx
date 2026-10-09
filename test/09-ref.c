#include <string.h>

#include "_tap.c"
#include "ref/sfinx_ref.c"
#include "src/sfinx.c"

#define MSG     "sfinx reference vector"
#define MSG_LEN (sizeof(MSG) - 1)

static const uint8_t SEED[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t PATH1[1] = {0x0a};
static const uint8_t PATH2[2] = {0x0a, 0x1b};

static void run_tree(int bits, sfinx_hash hash, size_t len, const uint8_t *path, size_t path_len) {
  uint8_t lib_pub[SFINX_HASH_LEN_MAX];
  uint8_t lib_sig[16384];
  uint8_t ref_sig[16384];
  uint8_t tamper[16384];
  size_t  n = sfinx_signature_len(hash, path_len);
  char    label[96];

  sfinx_tree_public_key(hash, SEED, sizeof(SEED), lib_pub, sizeof(lib_pub), NULL);
  sfinx_tree_sign(hash, SEED, sizeof(SEED), path, path_len, (const uint8_t *)MSG, MSG_LEN, lib_sig, sizeof(lib_sig),
                  NULL);
  ref_tree_sign(bits, SEED, sizeof(SEED), path, path_len, (const uint8_t *)MSG, MSG_LEN, ref_sig);

  snprintf(label, sizeof(label), "L%zu N%zu signature matches reference", len, path_len);
  tap(memcmp(lib_sig, ref_sig, n) == 0, label, "differs");

  snprintf(label, sizeof(label), "L%zu N%zu library verifies the reference", len, path_len);
  tap(sfinx_verify(lib_pub, len, (const uint8_t *)MSG, MSG_LEN, ref_sig, n) == SFINX_OK, label, "rejected");

  snprintf(label, sizeof(label), "L%zu N%zu reference verifies the library", len, path_len);
  tap(ref_verify(lib_pub, len, (const uint8_t *)MSG, MSG_LEN, lib_sig, n) != 0, label, "rejected");

  memcpy(tamper, ref_sig, n);
  tamper[2 + path_len] ^= 0x01;
  snprintf(label, sizeof(label), "L%zu N%zu tampered reference fails", len, path_len);
  tap(sfinx_verify(lib_pub, len, (const uint8_t *)MSG, MSG_LEN, tamper, n) != SFINX_OK, label, "accepted");

  memcpy(tamper, lib_sig, n);
  tamper[n - 1] ^= 0x01;
  snprintf(label, sizeof(label), "L%zu N%zu tampered library fails", len, path_len);
  tap(ref_verify(lib_pub, len, (const uint8_t *)MSG, MSG_LEN, tamper, n) == 0, label, "accepted");

  memcpy(tamper, lib_sig, n);
  ref_e4m4_encode((uint32_t)(len == 32 ? 64 : 32), tamper + 1 + path_len);
  snprintf(label, sizeof(label), "L%zu N%zu reference rejects a wrong E4M4(L)", len, path_len);
  tap(ref_verify(lib_pub, len, (const uint8_t *)MSG, MSG_LEN, tamper, n) == 0, label, "accepted");
}

static void run_bits(int bits) {
  sfinx_hash hash = (sfinx_hash)bits;
  size_t     len  = sfinx_hash_len(hash);
  uint8_t    lib_pub[SFINX_HASH_LEN_MAX];
  uint8_t    ref_pub[SFINX_HASH_LEN_MAX];
  uint8_t    lib_sig[16384];
  uint8_t    ref_sig[16384];
  size_t     n;
  char       label[96];

  sfinx_single_public_key(hash, SEED, sizeof(SEED), lib_pub, sizeof(lib_pub), NULL);
  ref_single_pub(bits, SEED, sizeof(SEED), ref_pub);
  snprintf(label, sizeof(label), "L%zu single pub matches reference", len);
  tap(memcmp(lib_pub, ref_pub, len) == 0, label, "differs");

  sfinx_tree_public_key(hash, SEED, sizeof(SEED), lib_pub, sizeof(lib_pub), NULL);
  ref_tree_pub(bits, SEED, sizeof(SEED), ref_pub);
  snprintf(label, sizeof(label), "L%zu tree pub matches reference", len);
  tap(memcmp(lib_pub, ref_pub, len) == 0, label, "differs");

  n = sfinx_signature_len(hash, 0);
  sfinx_single_sign(hash, SEED, sizeof(SEED), (const uint8_t *)MSG, MSG_LEN, lib_sig, sizeof(lib_sig), NULL);
  ref_single_sign(bits, SEED, sizeof(SEED), (const uint8_t *)MSG, MSG_LEN, ref_sig);
  snprintf(label, sizeof(label), "L%zu single signature matches reference", len);
  tap(memcmp(lib_sig, ref_sig, n) == 0, label, "differs");

  run_tree(bits, hash, len, PATH1, sizeof(PATH1));
  if (bits == 224 || bits == 256) {
    run_tree(bits, hash, len, PATH2, sizeof(PATH2));
  }
}

int main(void) {
  tap_begin("sfinx reference differential");

  run_bits(224);
  run_bits(256);
  run_bits(384);
  run_bits(512);

  return tap_plan();
}
