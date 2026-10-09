#include <string.h>

#include "_tap.c"
#include "src/sfinx.c"

int main(void) {
  static const uint8_t raw[8]   = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  static const uint8_t badhex[] = "zz";
  uint8_t              out[64];
  uint8_t              back[64];
  size_t               out_len  = 0;
  size_t               back_len = 0;
  size_t               need     = 0;
  sfinx_status         status;

  tap_begin("sfinx signature formats");

  status = sfinx_sig_decode(raw, sizeof(raw), "raw", out, sizeof(out), &out_len);
  tap(status == SFINX_OK, "raw decode", "%s", sfinx_strerror(status));
  tap(out_len == sizeof(raw) && memcmp(out, raw, sizeof(raw)) == 0, "raw is the identity", "mismatch");

  need = sfinx_sig_encode_len(raw, sizeof(raw), "hex");
  tap(need == sizeof(raw) * 2, "hex encode_len", "got %zu", need);
  status = sfinx_sig_encode(raw, sizeof(raw), "hex", out, sizeof(out), &out_len);
  tap(status == SFINX_OK, "hex encode", "%s", sfinx_strerror(status));
  tap(out_len == sizeof(raw) * 2 && memcmp(out, "0123456789abcdef", 16) == 0, "hex text", "got %.*s", (int)out_len,
      out);

  status = sfinx_sig_decode(out, out_len, "hex", back, sizeof(back), &back_len);
  tap(status == SFINX_OK, "hex decode", "%s", sfinx_strerror(status));
  tap(back_len == sizeof(raw) && memcmp(back, raw, sizeof(raw)) == 0, "hex round trip", "mismatch");

  need   = sfinx_sig_encode_len(raw, sizeof(raw), "hdr");
  status = sfinx_sig_encode(raw, sizeof(raw), "hdr", out, sizeof(out), &out_len);
  tap(status == SFINX_OK, "hdr encode", "%s", sfinx_strerror(status));
  tap(need == out_len, "hdr encode_len", "got %zu want %zu", need, out_len);
  status = sfinx_sig_decode(out, out_len, NULL, back, sizeof(back), &back_len);
  tap(status == SFINX_OK, "hdr auto-detect", "%s", sfinx_strerror(status));
  tap(back_len == sizeof(raw) && memcmp(back, raw, sizeof(raw)) == 0, "hdr round trip", "mismatch");

  status = sfinx_sig_decode(raw, sizeof(raw), NULL, back, sizeof(back), &back_len);
  tap(status == SFINX_OK && back_len == sizeof(raw), "auto falls back to raw", "%s", sfinx_strerror(status));

  status = sfinx_sig_decode(badhex, sizeof(badhex) - 1, "hex", back, sizeof(back), &back_len);
  tap(status == SFINX_ERR_FORMAT, "hex rejects bad input", "got %s", sfinx_strerror(status));

  status = sfinx_sig_decode(raw, sizeof(raw), "nope", back, sizeof(back), &back_len);
  tap(status == SFINX_ERR_FORMAT, "rejects an unknown format", "got %s", sfinx_strerror(status));

  status = sfinx_sig_encode(raw, sizeof(raw), "hex", out, 4, &out_len);
  tap(status == SFINX_ERR_NOSPACE, "hex encode rejects a small cap", "got %s", sfinx_strerror(status));

  return tap_plan();
}
