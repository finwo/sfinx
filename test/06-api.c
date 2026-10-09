#include "src/sfinx.c"
#include "_tap.c"

#include <string.h>

static void check_size(size_t got, size_t want, const char *what) {
  tap(got == want, what, "got %zu, want %zu", got, want);
}

int main(void) {
  uint8_t    sig[3]    = {0x01, 0xaa, 0x20};
  uint8_t    bad[3]    = {0x41, 0xaa, 0x20};
  sfinx_hash hash      = SFINX_HASH_224;
  size_t     path_len  = 99;

  tap_begin("sfinx api");

  check_size(sfinx_hash_len(SFINX_HASH_256), 32, "hash_len 256");
  check_size(sfinx_signature_len(SFINX_HASH_256, 0), 1090, "signature_len N=0");
  check_size(sfinx_signature_len(SFINX_HASH_256, 1), 1347, "signature_len N=1");
  check_size(sfinx_signature_len(SFINX_HASH_256, 32), 2 + 32 + 32 * 1344, "signature_len N=32");
  check_size(sfinx_signature_len_max(SFINX_HASH_256), sfinx_signature_len(SFINX_HASH_256, SFINX_PATH_LEN_MAX),
             "signature_len_max");

  tap(sfinx_path_len_valid(0), "path_len 0 valid", "rejected");
  tap(sfinx_path_len_valid(32), "path_len 32 valid", "rejected");
  tap(!sfinx_path_len_valid(33), "path_len 33 invalid", "accepted");
  tap(!sfinx_path_len_valid(63), "path_len 63 invalid", "accepted");
  tap(sfinx_path_len_valid(64), "path_len 64 valid", "rejected");
  tap(!sfinx_path_len_valid(SFINX_PATH_LEN_MAX + 1), "path_len over max invalid", "accepted");

  tap(strcmp(sfinx_strerror(SFINX_OK), "ok") == 0, "strerror ok", "got %s", sfinx_strerror(SFINX_OK));
  tap(sfinx_version()[0] != '\0', "version non-empty", "empty");

  tap(sfinx_signature_info(sig, sizeof(sig), &hash, &path_len) == SFINX_OK, "signature_info parses", "failed");
  check_size(path_len, 1, "signature_info path_len");
  tap(hash == SFINX_HASH_256, "signature_info hash", "got %d", (int)hash);
  tap(sfinx_signature_info(sig, sizeof(sig), NULL, NULL) == SFINX_OK, "signature_info accepts NULL outs", "failed");
  tap(sfinx_signature_info(bad, sizeof(bad), NULL, NULL) == SFINX_ERR_FORMAT, "signature_info rejects bad N", "accepted");

  return tap_plan();
}
