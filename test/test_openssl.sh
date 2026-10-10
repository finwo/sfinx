#!/bin/sh
# Anchors the sfinx hash wrappers to the openssl CLI, no Python.
# Skips cleanly when openssl or od is absent.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

CC=${CC:-cc}

tap_begin "openssl hash anchor"

if ! command -v openssl >/dev/null 2>&1 || ! command -v od >/dev/null 2>&1; then
  # No helper to call, so write the lone skip assertion directly
  printf 'TAP version 13\n'
  printf '# openssl hash anchor\n'
  printf 'ok 1 - openssl and od available # SKIP openssl or od not installed\n'
  printf '1..1\n'
  exit 0
fi
tap 1 "openssl and od available" ""

TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

HASH_FIRST="${ROOT}/lib/finwo/keccak-fast/src/keccak-fast.c"
HASH="${HASH_FIRST} ${ROOT}/lib/finwo/keccak-fast/src/backend/scalar.c ${ROOT}/lib/finwo/keccak-fast/src/backend/scalar_bmi.c ${ROOT}/lib/finwo/keccak-fast/src/backend/avx2.c ${ROOT}/lib/finwo/keccak-fast/src/backend/avx512.c"
if [ ! -f "${HASH_FIRST}" ]; then
  (cd "${ROOT}" && dep install) >/dev/null 2>&1 || true
fi

if "${CC}" -Wall -Wextra -O2 -I"${ROOT}" -I"${ROOT}/src" -I"${ROOT}/lib/.dep/include" \
  "${HERE}/ref/hash.c" ${HASH} -o "${TMP}/hash" >"${TMP}/build.log" 2>&1; then
  tap 1 "hash helper builds" ""
else
  tap 0 "hash helper builds" "$(cat "${TMP}/build.log")"
fi

# Inputs: empty, a short string, and a 200-byte pattern that crosses the SHAKE rate
: >"${TMP}/empty"
printf 'abc' >"${TMP}/abc"
i=0
: >"${TMP}/pattern"
while [ $i -lt 200 ]; do
  printf "\\$(printf '%03o' $((i % 256)))" >>"${TMP}/pattern"
  i=$((i + 1))
done

for f in empty abc pattern; do
  for h in 224 256 384 512; do
    got=$("${TMP}/hash" $h <"${TMP}/$f")
    want=$(openssl dgst -sha3-$h -binary <"${TMP}/$f" | od -An -v -tx1 | tr -d ' \n')
    tap "$([ "$got" = "$want" ] && echo 1 || echo 0)" "sha3-$h $f" "got $got want $want"
  done
done

# -xoflen is mandatory for SHAKE on openssl 3, probe before the group
if printf '' | openssl dgst -shake256 -xoflen 16 -binary >/dev/null 2>&1; then
  for f in empty abc pattern; do
    for n in 16 32 64 200; do
      got=$("${TMP}/hash" shake $n <"${TMP}/$f")
      want=$(openssl dgst -shake256 -xoflen $n -binary <"${TMP}/$f" | od -An -v -tx1 | tr -d ' \n')
      tap "$([ "$got" = "$want" ] && echo 1 || echo 0)" "shake256 $n $f" "got $got want $want"
    done
  done
else
  tap 0 "openssl dgst supports -shake256 -xoflen" "not supported by this openssl"
fi

tap_plan
