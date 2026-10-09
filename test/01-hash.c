#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

static void check_size(size_t got, size_t want, const char *what) {
  tap(got == want, what, "got %zu, want %zu", got, want);
}

static void hex_encode(const uint8_t *in, size_t len, char *out) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[2 * i]     = digits[in[i] >> 4];
    out[2 * i + 1] = digits[in[i] & 0x0f];
  }
  out[2 * len] = '\0';
}

static void check_hash(const char *what, sfinx_hash hash, const char *in, const char *want) {
  uint8_t digest[SFINX_HASH_LEN_MAX];
  char    got[SFINX_HASH_LEN_MAX * 2 + 1];
  size_t  len = sfinx_hash_len(hash);
  _sfinx_hash(hash, (const uint8_t *)in, strlen(in), digest);
  hex_encode(digest, len, got);
  tap(strcmp(got, want) == 0, what, "got %s, want %s", got, want);
}

static void check_shake(const char *what, const char *in, size_t out_len, const char *want) {
  uint8_t digest[SFINX_HASH_LEN_MAX];
  char    got[SFINX_HASH_LEN_MAX * 2 + 1];
  _sfinx_shake256((const uint8_t *)in, strlen(in), digest, out_len);
  hex_encode(digest, out_len, got);
  tap(strcmp(got, want) == 0, what, "got %s, want %s", got, want);
}

int main(void) {
  tap_begin("sfinx hash backend");

  check_size(sfinx_hash_len(SFINX_HASH_224), 28, "hash_len 224");
  check_size(sfinx_hash_len(SFINX_HASH_256), 32, "hash_len 256");
  check_size(sfinx_hash_len(SFINX_HASH_384), 48, "hash_len 384");
  check_size(sfinx_hash_len(SFINX_HASH_512), 64, "hash_len 512");
  check_size(sfinx_hash_len((sfinx_hash)123), 0, "hash_len invalid");

  check_hash("SHA3-224 empty", SFINX_HASH_224, "", "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
  check_hash("SHA3-256 empty", SFINX_HASH_256, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  check_hash("SHA3-384 empty", SFINX_HASH_384, "",
             "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a"
             "c3713831264adb47fb6bd1e058d5f004");
  check_hash("SHA3-512 empty", SFINX_HASH_512, "",
             "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
             "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");

  check_hash("SHA3-224 abc", SFINX_HASH_224, "abc", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
  check_hash("SHA3-256 abc", SFINX_HASH_256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  check_hash("SHA3-384 abc", SFINX_HASH_384, "abc",
             "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2"
             "98d88cea927ac7f539f1edf228376d25");
  check_hash("SHA3-512 abc", SFINX_HASH_512, "abc",
             "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
             "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

  check_shake("SHAKE256 empty 16", "", 16, "46b9dd2b0ba88d13233b3feb743eeb24");
  check_shake("SHAKE256 empty 32", "", 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
  check_shake("SHAKE256 empty 64", "", 64,
              "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
              "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
  check_shake("SHAKE256 abc 32", "abc", 32, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");

  return tap_plan();
}
