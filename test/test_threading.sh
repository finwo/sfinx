#!/bin/sh
# Builds the thread dump with and without -pthread and diffs the signatures.
# A ThreadSanitizer build runs too, and is skipped when it does not build.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

CC=${CC:-cc}

tap_begin "sfinx threading"

HASH_FIRST="${ROOT}/lib/finwo/keccak-fast/src/keccak-fast.c"
HASH="${HASH_FIRST} ${ROOT}/lib/finwo/keccak-fast/src/backend/scalar.c ${ROOT}/lib/finwo/keccak-fast/src/backend/scalar_bmi.c ${ROOT}/lib/finwo/keccak-fast/src/backend/avx2.c ${ROOT}/lib/finwo/keccak-fast/src/backend/avx512.c"
if [ ! -f "${HASH_FIRST}" ]; then
  (cd "${ROOT}" && dep install) >/dev/null 2>&1 || true
fi

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

build() {
  out=$1
  shift
  "${CC}" -Wall -Wextra -O2 "$@" -I"${ROOT}" -I"${ROOT}/src" -I"${ROOT}/lib/.dep/include" \
    "${HERE}/ref/thread_dump.c" ${HASH} -o "${out}"
}

if build "${TMP}/threaded" -pthread >"${TMP}/b1.log" 2>&1; then
  tap 1 "threaded dump builds" ""
else
  tap 0 "threaded dump builds" "$(cat "${TMP}/b1.log")"
fi
if build "${TMP}/plain" >"${TMP}/b2.log" 2>&1; then
  tap 1 "plain dump builds" ""
else
  tap 0 "plain dump builds" "$(cat "${TMP}/b2.log")"
fi

"${TMP}/threaded" >"${TMP}/a" 2>/dev/null || true
"${TMP}/plain" >"${TMP}/b" 2>/dev/null || true
if [ -s "${TMP}/a" ] && cmp -s "${TMP}/a" "${TMP}/b"; then
  tap 1 "threaded and plain signatures match" ""
else
  tap 0 "threaded and plain signatures match" "dump outputs differ or are empty"
fi

if build "${TMP}/tsan" -pthread -fsanitize=thread >"${TMP}/b3.log" 2>&1; then
  if TSAN_OPTIONS="halt_on_error=1" "${TMP}/tsan" >"${TMP}/t.log" 2>&1; then
    tap 1 "thread sanitizer reports no races" ""
  else
    tap 0 "thread sanitizer reports no races" "$(tail -n 5 "${TMP}/t.log" 2>/dev/null || true)"
  fi
else
  TAP_NO=$((TAP_NO + 1))
  printf 'ok %s - thread sanitizer available # SKIP TSan build failed\n' "${TAP_NO}"
fi

tap_plan
