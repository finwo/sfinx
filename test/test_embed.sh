#!/bin/sh
# Reads export.mk for the library source list, compiles a program that includes
# only sfinx.h against that list plus keccak-tiny, then exercises the crypto and
# the key format API. No CLI, no util, no argparse, no rxi/log is reachable.
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

# export.mk, templated the way dep does it, expanded the way make does it
sed "s|{{module.dirname}}|${ROOT}|g" "${ROOT}/export.mk" >"${TMP}/export.mk"
printf 'include %s\nprobe:\n\t@echo $(SRC)\n' "${TMP}/export.mk" >"${TMP}/probe.mk"
LIB_SRCS=$(make -s -f "${TMP}/probe.mk" probe 2>/dev/null || true)
if [ -n "${LIB_SRCS}" ]; then
  tap 1 "export.mk yields library sources" ""
else
  tap 0 "export.mk yields library sources" "probe produced nothing"
fi

missing=""
for f in ${LIB_SRCS}; do
  [ -f "$f" ] || missing="${missing} ${f}"
done
if [ -z "${missing}" ]; then
  tap 1 "library sources exist" ""
else
  tap 0 "library sources exist" "missing:${missing}"
fi

bad=""
for f in ${LIB_SRCS}; do
  hit=$(grep -E '^[[:space:]]*#include' "$f" | grep -E 'cli/|util/|argparse|log\.h' || true)
  [ -z "${hit}" ] || bad="${bad}${f} ${hit}; "
done
if [ -z "${bad}" ]; then
  tap 1 "library sources have no util includes" ""
else
  tap 0 "library sources have no util includes" "${bad}"
fi

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
  uint8_t              hdr[4096];
  size_t               pub_len = 0;
  size_t               sig_len = 0;
  size_t               hdr_len = 0;
  size_t               msg_len = sizeof(msg) - 1;
  sfinx_key            key;
  sfinx_key            reread;
  sfinx_status         status;

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

  status = sfinx_key_decode(seed, sizeof(seed), "raw", &key);
  if (status != SFINX_OK) {
    return fail("decode raw");
  }
  if (sfinx_key_derive(&key) != SFINX_OK) {
    return fail("derive");
  }
  if (key.pub_len != pub_len || memcmp(key.pub, pub, pub_len) != 0) {
    return fail("derived pub mismatch");
  }
  if (sfinx_key_encode_len(&key, "hdr") == 0) {
    return fail("encode_len hdr");
  }
  if (sfinx_key_encode(&key, "hdr", hdr, sizeof(hdr), &hdr_len) != SFINX_OK) {
    return fail("encode hdr");
  }
  status = sfinx_key_decode(hdr, hdr_len, NULL, &reread);
  if (status != SFINX_OK) {
    return fail("decode hdr auto");
  }
  if (reread.pub_len != pub_len || memcmp(reread.pub, pub, pub_len) != 0) {
    return fail("hdr pub mismatch");
  }
  sfinx_key_free(&key);
  sfinx_key_free(&reread);
  return 0;
}
EOF

if "${CC}" -Wall -Wextra -O2 -I"${ROOT}/src" -I"${ROOT}/lib/.dep/include" "${TMP}/embed.c" ${LIB_SRCS} \
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
  tap 1 "embed crypto and format round trip" ""
else
  tap 0 "embed crypto and format round trip" "exit ${rc}: $(cat "${TMP}/run.log" 2>/dev/null || true)"
fi

tap_plan
