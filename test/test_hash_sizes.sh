#!/bin/sh
# Round trips every hash size through the CLI and checks the E4M4(L) negative.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

bytes() {
  wc -c <"$1" | tr -d '[:space:]'
}

size_n1() {
  # 2 + N + N * (L + 10) * L with N = 1
  echo $((3 + ($1 + 10) * $1))
}

patch_byte() {
  # patch_byte <file> <offset> <decimal>
  printf "\\$(printf '%03o' "$3")" | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null
}

tap_begin "cli: hash sizes"

for L in 28 32 48 64; do
  bits=$((L * 8))
  "${BIN}" generate --out-fmt raw -L $bits -o "${TMP}/k$L.key"
  "${BIN}" sign -k "${TMP}/k$L.key" -L $bits -P 0a -m 'hash size' -o "${TMP}/s$L.sig"

  n=$(bytes "${TMP}/s$L.sig")
  tap "$([ "${n}" = "$(size_n1 $L)" ] && echo 1 || echo 0)" "L$L N1 signature is $(size_n1 $L) bytes" \
    "got ${n}"
  tap "$([ "$(bytes "${TMP}/k$L.pub")" = "${L}" ] && echo 1 || echo 0)" "L$L public key is ${L} bytes" \
    "got $(bytes "${TMP}/k$L.pub")"

  "${BIN}" verify -k "${TMP}/k$L.pub" -L $bits -m 'hash size' -S "${TMP}/s$L.sig" >/dev/null && ok=1 || ok=0
  tap "${ok}" "L$L round trip verifies" "failed"
done

# E4M4(L) at offset 1 + N = 2 in the L32 signature must match the public key length
cp "${TMP}/s32.sig" "${TMP}/bad-l.sig"
patch_byte "${TMP}/bad-l.sig" 2 48
rc=0
"${BIN}" verify -k "${TMP}/k32.pub" -m 'hash size' -S "${TMP}/bad-l.sig" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "E4M4(L) 64 against a 32-byte key fails" "exit ${rc}"

cp "${TMP}/s32.sig" "${TMP}/bad-l2.sig"
patch_byte "${TMP}/bad-l2.sig" 2 31
rc=0
"${BIN}" verify -k "${TMP}/k32.pub" -m 'hash size' -S "${TMP}/bad-l2.sig" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "an invalid E4M4(L) fails" "exit ${rc}"

tap_plan
