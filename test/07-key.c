#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

int main(void) {
  static const uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                   0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                   0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t badhdr[] = "public-key: zzzz\n";
  uint8_t              hdr[4096];
  size_t               hdr_len = 0;
  size_t               need    = 0;
  sfinx_key            key;
  sfinx_key            other;
  sfinx_key            badkey;
  sfinx_status         status;

  tap_begin("sfinx key");

  sfinx_key_init(&key);
  tap(key.hash == SFINX_HASH_DEFAULT, "init sets the default hash", "got %d", (int)key.hash);
  tap(key.seed == NULL && key.pub == NULL, "init zeroes both halves", "not zeroed");

  status = sfinx_key_decode(seed, sizeof(seed), "raw", &key);
  tap(status == SFINX_OK, "decode raw", "%s", sfinx_strerror(status));
  tap(key.seed_len == sizeof(seed), "raw seed length", "got %zu", key.seed_len);
  tap(key.pub == NULL, "raw has no pub yet", "pub present");

  status = sfinx_key_derive(&key);
  tap(status == SFINX_OK, "derive", "%s", sfinx_strerror(status));
  tap(key.pub_len == 32, "derived pub length", "got %zu", key.pub_len);

  need = sfinx_key_encode_len(&key, "hdr");
  tap(need > 0, "hdr encode_len", "got %zu", need);
  status = sfinx_key_encode(&key, "hdr", hdr, sizeof(hdr), &hdr_len);
  tap(status == SFINX_OK, "encode hdr", "%s", sfinx_strerror(status));
  tap(hdr_len == need, "hdr length matches encode_len", "got %zu want %zu", hdr_len, need);

  status = sfinx_key_decode(hdr, hdr_len, NULL, &other);
  tap(status == SFINX_OK, "decode hdr auto", "%s", sfinx_strerror(status));
  tap(other.pub_len == key.pub_len && memcmp(other.pub, key.pub, key.pub_len) == 0, "hdr pub matches", "mismatch");
  tap(other.seed_len == key.seed_len && memcmp(other.seed, key.seed, key.seed_len) == 0, "hdr seed matches",
      "mismatch");

  free(other.seed);
  other.seed     = NULL;
  other.seed_len = 0;
  need           = sfinx_key_encode_len(&other, "raw");
  tap(need == other.pub_len, "raw pub encode_len", "got %zu", need);

  status = sfinx_key_encode(&key, "hdr", hdr, 1, &hdr_len);
  tap(status == SFINX_ERR_NOSPACE, "hdr encode rejects a small cap", "got %s", sfinx_strerror(status));

  sfinx_key_init(&badkey);
  status = sfinx_key_decode(seed, sizeof(seed), "nope", &badkey);
  tap(status == SFINX_ERR_FORMAT, "decode rejects an unknown format", "got %s", sfinx_strerror(status));
  status = sfinx_key_decode(badhdr, sizeof(badhdr) - 1, NULL, &badkey);
  tap(status == SFINX_ERR_FORMAT, "decode rejects bad hex", "got %s", sfinx_strerror(status));

  sfinx_key_free(&key);
  sfinx_key_free(&other);
  sfinx_key_free(&badkey);
  return tap_plan();
}
