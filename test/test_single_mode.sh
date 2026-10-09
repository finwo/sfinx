#!/bin/sh
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

tap_begin "cli: single-key mode"

"${BIN}" generate --single --out-fmt raw -o "${TMP}/s.key"
tap "$([ "$(bytes "${TMP}/s.key")" = 32 ] && [ "$(bytes "${TMP}/s.pub")" = 32 ] && echo 1 || echo 0)" \
  "single generate writes a seed and a public key" "key $(bytes "${TMP}/s.key") pub $(bytes "${TMP}/s.pub")"

"${BIN}" sign --single -k "${TMP}/s.key" -m hello -o "${TMP}/sig.bin"
tap "$([ "$(bytes "${TMP}/sig.bin")" = 1090 ] && echo 1 || echo 0)" "single signature is size(0) bytes" \
  "got $(bytes "${TMP}/sig.bin")"

"${BIN}" verify -k "${TMP}/s.pub" -m hello -S "${TMP}/sig.bin" >/dev/null && ok=1 || ok=0
tap "${ok}" "single signature verifies with the public key" "failed"

"${BIN}" sign --single -k "${TMP}/s.key" -m hello -o "${TMP}/a.bin"
"${BIN}" sign --single -k "${TMP}/s.key" -m hello -o "${TMP}/b.bin"
cmp -s "${TMP}/a.bin" "${TMP}/b.bin" && ok=1 || ok=0
tap "${ok}" "single signing is deterministic" "differs"

"${BIN}" printkey --in-fmt raw -k "${TMP}/s.key" --out-fmt rawpub --public-only >"${TMP}/tree.pub"
cmp -s "${TMP}/tree.pub" "${TMP}/s.pub" && ok=0 || ok=1
tap "${ok}" "single and tree public keys differ for one seed" "same key"

rc=0
"${BIN}" verify -k "${TMP}/tree.pub" -m hello -S "${TMP}/sig.bin" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "a tree public key rejects a single signature" "exit ${rc}"

"${BIN}" printkey --in-fmt raw -k "${TMP}/s.key" --single --out-fmt rawpub --public-only >"${TMP}/single.pub"
cmp -s "${TMP}/single.pub" "${TMP}/s.pub" && ok=1 || ok=0
tap "${ok}" "printkey --single matches the generated public key" "differs"

"${BIN}" generate --single -o "${TMP}/h.hdr"
"${BIN}" sign --single -k "${TMP}/h.hdr" -m hello -o "${TMP}/h.sig"
"${BIN}" verify -k "${TMP}/h.hdr" -m hello -S "${TMP}/h.sig" >/dev/null && ok=1 || ok=0
tap "${ok}" "verify derives the single key from a seed-bearing hdr" "failed"

rc=0
"${BIN}" sign --single -k "${TMP}/s.key" -m hi -P 0011 >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "--single refuses --path" "exit ${rc}"

rc=0
"${BIN}" sign --single -k "${TMP}/s.key" -m hi -p 8 >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "--single refuses --path-len" "exit ${rc}"

out=$("${BIN}" sign -p 0 -k "${TMP}/s.key" -m hi 2>&1 || true)
case "${out}" in *--single*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "-p 0 names --single in the error" "${out}"

tap_plan
