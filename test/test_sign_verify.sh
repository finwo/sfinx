#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

tap_begin "cli: sign and verify"

"${BIN}" seed -o "${TMP}/seed.bin"
"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" -o "${TMP}/key.hdr"
"${BIN}" printkey -k "${TMP}/key.hdr" --public-only -o "${TMP}/pub.hdr"

"${BIN}" sign -k "${TMP}/key.hdr" -m hello -P 0011 -o "${TMP}/sig.bin"
"${BIN}" verify -k "${TMP}/pub.hdr" -m hello -S "${TMP}/sig.bin" >/dev/null && ok=1 || ok=0
tap "${ok}" "raw signature file round trip" "failed"

"${BIN}" sign -k "${TMP}/key.hdr" -m hello -P 0011 -o "${TMP}/a.bin"
"${BIN}" sign -k "${TMP}/key.hdr" -m hello -P 0011 -o "${TMP}/b.bin"
cmp -s "${TMP}/a.bin" "${TMP}/b.bin" && ok=1 || ok=0
tap "${ok}" "fixed path is deterministic" "differs"

HEX=$("${BIN}" sign -k "${TMP}/key.hdr" -m hello -P 0011)
"${BIN}" verify -k "${TMP}/pub.hdr" -m hello -s "${HEX}" >/dev/null && ok=1 || ok=0
tap "${ok}" "hex signature with -s" "failed"

"${BIN}" sign -k "${TMP}/key.hdr" -m hello -P 0011 --sig-fmt hdr |
  "${BIN}" verify -k "${TMP}/pub.hdr" -m hello >/dev/null && ok=1 || ok=0
tap "${ok}" "hdr signature auto-detected from stdin" "failed"

"${BIN}" printkey -k "${TMP}/key.hdr" --public-only --out-fmt rawpub >"${TMP}/pub.bin"
"${BIN}" sign --key-fmt raw -k "${TMP}/seed.bin" -m hello -P 0011 --sig-fmt hex -o "${TMP}/sig.hex"
"${BIN}" verify --key-fmt rawpub -k "${TMP}/pub.bin" --sig-fmt hex -m hello -S "${TMP}/sig.hex" >/dev/null && ok=1 || ok=0
tap "${ok}" "explicit key-fmt and sig-fmt round trip" "failed"

"${BIN}" printkey -k "${TMP}/key.hdr" --public-only --out-fmt hexpub >"${TMP}/pub.hex"
"${BIN}" verify --key-fmt hexpub -k "${TMP}/pub.hex" -m hello -S "${TMP}/sig.bin" >/dev/null && ok=1 || ok=0
tap "${ok}" "hexpub key reads back" "failed"

printf 'hello' >"${TMP}/msg"
"${BIN}" verify -k "${TMP}/pub.hdr" -M "${TMP}/msg" -S "${TMP}/sig.bin" >/dev/null && ok=1 || ok=0
tap "${ok}" "message from a file" "failed"

printf 'hello' | "${BIN}" verify -k "${TMP}/pub.hdr" -S "${TMP}/sig.bin" >/dev/null && ok=1 || ok=0
tap "${ok}" "message from stdin" "failed"

rc=0
"${BIN}" verify -k "${TMP}/pub.hdr" -m nope -S "${TMP}/sig.bin" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "tampered message fails" "exit ${rc}"

rc=0
"${BIN}" verify -k "${TMP}/pub.hdr" -m hello -L 512 -S "${TMP}/sig.bin" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "hash mismatch fails" "exit ${rc}"

rc=0
"${BIN}" verify -k "${TMP}/pub.hdr" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "both inputs on stdin fails" "exit ${rc}"

tap_plan
