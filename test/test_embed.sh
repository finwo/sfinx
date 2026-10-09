#!/bin/sh
# test/test_embed.sh - prove sfinx stands alone as a library.
#
# Compiles a program that includes only sfinx.h and links only sfinx.c plus
# keccak-tiny, then runs an N=2 tree round trip with tamper checks. No CLI, no
# util, no argparse, no rxi/log path is reachable, so a leaked dependency
# breaks the build instead of passing silently.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

CC=${CC:-cc}
KECCAK="${ROOT}/lib/coruus/keccak-tiny/keccak-tiny.c"

tap_begin "embed: library stands alone"

if [ -f "${ROOT}/src/sfinx.h" ] && [ -f "${ROOT}/src/sfinx.c" ]; then
  tap 1 "sources present" ""
else
  tap 0 "sources present" "missing src/sfinx.h or src/sfinx.c"
fi

bad=$(grep -E '^[[:space:]]*#include' "${ROOT}/src/sfinx.h" |
  grep -vE '^[[:space:]]*#include[[:space:]]+<(stddef|stdint)\.h>' || true)
if [ -z "${bad}" ]; then
  tap 1 "sfinx.h includes only stddef and stdint" ""
else
  tap 0 "sfinx.h includes only stddef and stdint" "${bad}"
fi

bad=$(grep -E '^[[:space:]]*#include' "${ROOT}/src/sfinx.c" |
  grep -E 'cli/|util/|argparse|log\.h' || true)
if [ -z "${bad}" ]; then
  tap 1 "sfinx.c has no util includes" ""
else
  tap 0 "sfinx.c has no util includes" "${bad}"
fi

if [ ! -f "${KECCAK}" ]; then
  (cd "${ROOT}" && dep install) >/dev/null 2>&1 || true
fi
if [ -f "${KECCAK}" ] && [ -f "${ROOT}/lib/.dep/include/coruus/keccak-tiny.h" ]; then
  tap 1 "root dep installed" ""
else
  tap 0 "root dep installed" "dep install did not provide keccak-tiny"
fi

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

cat >"${TMP}/embed.c" <<'EOF'
#include "sfinx.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *stage) {
  fprintf(stderr, "embed: %s\n", stage);
  return 1;
}

int main(void) {
  static const uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                   0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                   0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  static const uint8_t path[2] = {0x12, 0x34};
  static const uint8_t msg[]   = "sfinx embed round trip";
  uint8_t              pub[SFINX_HASH_LEN_MAX];
  uint8_t              sig[4096];
  uint8_t              tamper[4096];
  size_t               pub_len = 0;
  size_t               sig_len = 0;
  size_t               msg_len = sizeof(msg) - 1;

  if (sfinx_tree_public_key(SFINX_HASH_256, seed, sizeof(seed), pub, sizeof(pub), &pub_len) != SFINX_OK) {
    return fail("tree_public_key");
  }
  if (sfinx_tree_sign(SFINX_HASH_256, seed, sizeof(seed), path, sizeof(path), msg, msg_len, sig, sizeof(sig),
                      &sig_len) != SFINX_OK) {
    return fail("tree_sign");
  }
  if (sfinx_verify(pub, pub_len, msg, msg_len, sig, sig_len) != SFINX_OK) {
    return fail("verify round trip");
  }

  memcpy(tamper, sig, sig_len);
  tamper[1] ^= 0x01;
  if (sfinx_verify(pub, pub_len, msg, msg_len, tamper, sig_len) == SFINX_OK) {
    return fail("tampered path accepted");
  }

  memcpy(tamper, sig, sig_len);
  tamper[sig_len - 1] ^= 0x01;
  if (sfinx_verify(pub, pub_len, msg, msg_len, tamper, sig_len) == SFINX_OK) {
    return fail("tampered proof accepted");
  }

  pub[0] ^= 0x01;
  if (sfinx_verify(pub, pub_len, msg, msg_len, sig, sig_len) == SFINX_OK) {
    return fail("tampered pubkey accepted");
  }

  return 0;
}
EOF

if "${CC}" -Wall -Wextra -O2 -I"${ROOT}/src" -I"${ROOT}/lib/.dep/include" "${TMP}/embed.c" "${ROOT}/src/sfinx.c" \
  "${KECCAK}" -o "${TMP}/embed" >"${TMP}/build.log" 2>&1; then
  tap 1 "embed program builds against the library only" ""
else
  tap 0 "embed program builds against the library only" "$(cat "${TMP}/build.log")"
fi

rc=0
if [ -x "${TMP}/embed" ]; then
  "${TMP}/embed" >"${TMP}/run.log" 2>&1 || rc=$?
else
  rc=127
fi
if [ "${rc}" = 0 ]; then
  tap 1 "embed N=2 round trip and tamper checks" ""
else
  tap 0 "embed N=2 round trip and tamper checks" "exit ${rc}: $(cat "${TMP}/run.log" 2>/dev/null || true)"
fi

tap_plan
