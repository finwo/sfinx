#include <inttypes.h>
#include <limits.h>

#include "_tap.c"
#include "src/sfinx.c"

static void check_u32(uint32_t got, uint32_t want, const char *what) {
  tap(got == want, what, "got %" PRIu32 ", want %" PRIu32, got, want);
}

static void check_encode(uint32_t value, uint8_t want, const char *what) {
  uint8_t got = 0xaa;
  if (_sfinx_e4m4_encode(value, &got)) {
    tap(got == want, what, "got 0x%02x, want 0x%02x", got, want);
  } else {
    tap(0, what, "encode(%" PRIu32 ") not representable", value);
  }
}

int main(void) {
  uint8_t  scratch  = 0;
  uint32_t round_ok = 1;
  int      bad      = -1;

  tap_begin("sfinx E4M4");

  check_u32(_sfinx_e4m4_decode(0x00), 0, "decode 0x00");
  check_u32(_sfinx_e4m4_decode(0x0f), 15, "decode 0x0f");
  check_u32(_sfinx_e4m4_decode(0x10), 16, "decode 0x10");
  check_u32(_sfinx_e4m4_decode(0x1c), 28, "decode 0x1c");
  check_u32(_sfinx_e4m4_decode(0x1f), 31, "decode 0x1f");
  check_u32(_sfinx_e4m4_decode(0x20), 32, "decode 0x20");
  check_u32(_sfinx_e4m4_decode(0x28), 48, "decode 0x28");
  check_u32(_sfinx_e4m4_decode(0x2f), 62, "decode 0x2f");
  check_u32(_sfinx_e4m4_decode(0x30), 64, "decode 0x30");
  check_u32(_sfinx_e4m4_decode(0x3f), 124, "decode 0x3f");
  check_u32(_sfinx_e4m4_decode(0x40), 128, "decode 0x40");
  check_u32(_sfinx_e4m4_decode(0xff), 507904, "decode 0xff");

  check_encode(0, 0x00, "encode 0");
  check_encode(15, 0x0f, "encode 15");
  check_encode(16, 0x10, "encode 16");
  check_encode(28, 0x1c, "encode 28 (L 224)");
  check_encode(32, 0x20, "encode 32 (N default)");
  check_encode(48, 0x28, "encode 48 (L 384)");
  check_encode(64, 0x30, "encode 64 (L 512)");
  check_encode(507904, 0xff, "encode max");

  check_u32(_sfinx_e4m4_encode(33, &scratch), 0, "reject 33");
  check_u32(_sfinx_e4m4_encode(63, &scratch), 0, "reject 63");
  check_u32(_sfinx_e4m4_encode(125, &scratch), 0, "reject 125");
  check_u32(_sfinx_e4m4_encode(507905, &scratch), 0, "reject max + 1");
  check_u32(_sfinx_e4m4_encode(524288, &scratch), 0, "reject 16 << 15");
  check_u32(_sfinx_e4m4_encode(INT_MAX, &scratch), 0, "reject INT_MAX");
  check_u32(_sfinx_e4m4_encode(UINT32_MAX, &scratch), 0, "reject UINT32_MAX");

  for (int i = 0; i < 256; i++) {
    uint8_t  round = 0;
    uint32_t value = _sfinx_e4m4_decode((uint8_t)i);
    if (!_sfinx_e4m4_encode(value, &round) || round != (uint8_t)i) {
      round_ok = 0;
      bad      = i;
      break;
    }
  }
  tap(round_ok, "every byte round trips", "byte 0x%02x did not", (unsigned)bad);

  return tap_plan();
}
