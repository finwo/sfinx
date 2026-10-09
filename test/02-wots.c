#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

static void check_size(size_t got, size_t want, const char *what) {
  tap(got == want, what, "got %zu, want %zu", got, want);
}

static void chain_manual(sfinx_hash hash, uint8_t *node, uint32_t steps) {
  uint8_t next[SFINX_HASH_LEN_MAX];
  size_t  len = sfinx_hash_len(hash);
  for (uint32_t i = 0; i < steps; i++) {
    _sfinx_hash(hash, node, len, next);
    memcpy(node, next, len);
  }
}

int main(void) {
  static const sfinx_hash hashes[] = {SFINX_HASH_224, SFINX_HASH_256, SFINX_HASH_384, SFINX_HASH_512};
  static const char      *labels[] = {"round trip 224", "round trip 256", "round trip 384", "round trip 512"};
  const uint8_t          *seed     = (const uint8_t *)"sfinx wots seed";
  size_t                  seed_len = strlen((const char *)seed);
  uint8_t                 zero[SFINX_HASH_LEN_MAX] = {0};
  uint8_t                 ones[SFINX_HASH_LEN_MAX];
  uint8_t                 value[SFINX_HASH_LEN_MAX];
  uint8_t                 digits[SFINX_WOTS_DIGITS_MAX];
  uint8_t                 pubkey[SFINX_HASH_LEN_MAX];
  uint8_t                 other[SFINX_HASH_LEN_MAX];
  uint8_t                 proof[SFINX_WOTS_BYTES_MAX];
  uint8_t                 node[SFINX_HASH_LEN_MAX];
  uint8_t                 manual[SFINX_HASH_LEN_MAX];

  tap_begin("sfinx WOTS");

  _sfinx_wots_digits(SFINX_HASH_256, zero, digits);
  check_size(digits[32], 0x1f, "checksum high, all zero");
  check_size(digits[33], 0xe0, "checksum low, all zero");

  memset(ones, 0xff, sizeof(ones));
  _sfinx_wots_digits(SFINX_HASH_256, ones, digits);
  check_size(digits[0], 0xff, "digit copies value, all one");
  check_size(digits[32], 0x00, "checksum high, all one");
  check_size(digits[33], 0x00, "checksum low, all one");

  _sfinx_wots_digits(SFINX_HASH_512, zero, digits);
  check_size(digits[64], 0x3f, "checksum high, L 64");
  check_size(digits[65], 0xc0, "checksum low, L 64");

  for (size_t i = 0; i < 32; i++) value[i] = (uint8_t)(i * 7 + 1);
  _sfinx_wots_digits(SFINX_HASH_256, value, digits);
  tap(memcmp(digits, value, 32) == 0, "digits copy the value", "digits differ");

  for (size_t i = 0; i < 32; i++) node[i] = (uint8_t)(i + 1);
  memcpy(manual, node, 32);
  chain_manual(SFINX_HASH_256, manual, 5);
  _sfinx_wots_chain(SFINX_HASH_256, node, 5);
  tap(memcmp(node, manual, 32) == 0, "chain of 5 matches manual", "chain differs");

  for (size_t i = 0; i < 32; i++) node[i] = (uint8_t)(i + 1);
  memcpy(manual, node, 32);
  _sfinx_wots_chain(SFINX_HASH_256, node, 0);
  tap(memcmp(node, manual, 32) == 0, "chain of 0 is identity", "chain changed");

  _sfinx_wots_pubkey(SFINX_HASH_256, seed, seed_len, pubkey);
  _sfinx_wots_pubkey(SFINX_HASH_256, seed, seed_len, other);
  tap(memcmp(pubkey, other, 32) == 0, "pubkey is deterministic", "pubkeys differ");

  _sfinx_wots_pubkey(SFINX_HASH_256, (const uint8_t *)"other wots seed", 15, other);
  tap(memcmp(pubkey, other, 32) != 0, "different seed gives a different pubkey", "pubkeys match");

  _sfinx_hash(SFINX_HASH_256, (const uint8_t *)"hello", 5, value);
  _sfinx_wots_proof(SFINX_HASH_256, seed, seed_len, value, proof);
  tap(_sfinx_wots_verify(SFINX_HASH_256, pubkey, value, proof), "proof verifies", "verify failed");

  proof[17] ^= 0x40;
  tap(!_sfinx_wots_verify(SFINX_HASH_256, pubkey, value, proof), "tampered proof fails", "verify passed");

  _sfinx_wots_proof(SFINX_HASH_256, seed, seed_len, value, proof);
  value[3] ^= 0x01;
  tap(!_sfinx_wots_verify(SFINX_HASH_256, pubkey, value, proof), "tampered value fails", "verify passed");

  _sfinx_hash(SFINX_HASH_256, (const uint8_t *)"hello", 5, value);
  _sfinx_wots_proof(SFINX_HASH_256, seed, seed_len, value, proof);
  memcpy(other, pubkey, 32);
  other[0] ^= 0x01;
  tap(!_sfinx_wots_verify(SFINX_HASH_256, other, value, proof), "wrong pubkey fails", "verify passed");

  for (size_t h = 0; h < 4; h++) {
    _sfinx_hash(hashes[h], (const uint8_t *)"message", 7, value);
    _sfinx_wots_pubkey(hashes[h], seed, seed_len, pubkey);
    _sfinx_wots_proof(hashes[h], seed, seed_len, value, proof);
    tap(_sfinx_wots_verify(hashes[h], pubkey, value, proof), labels[h], "verify failed");
  }

  return tap_plan();
}
