#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

tap_begin "cli: printkey"

"${BIN}" seed -o "${TMP}/seed.bin"

"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" >"${TMP}/key.hdr"
grep -q '^public-key: ' "${TMP}/key.hdr" && ok=1 || ok=0
tap "${ok}" "raw seed converts to hdr" "$(cat "${TMP}/key.hdr")"

"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" --public-only >"${TMP}/a.hdr"
"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" --public-only >"${TMP}/b.hdr"
cmp -s "${TMP}/a.hdr" "${TMP}/b.hdr" && ok=1 || ok=0
tap "${ok}" "same seed gives the same key" "differs"

"${BIN}" printkey -k "${TMP}/key.hdr" --public-only --out-fmt raw >"${TMP}/pub.bin"
n=$(wc -c <"${TMP}/pub.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 32 ] && echo 1 || echo 0)" "hdr auto-detect gives a 32-byte pub" "got ${n}"

"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" -L 512 --public-only --out-fmt raw >"${TMP}/pub512.bin"
n=$(wc -c <"${TMP}/pub512.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 64 ] && echo 1 || echo 0)" "--hash 512 gives a 64-byte pub" "got ${n}"

"${BIN}" printkey -k "${TMP}/key.hdr" -L 512 --public-only --out-fmt rawpub >"${TMP}/pub512.stale"
cmp -s "${TMP}/pub512.stale" "${TMP}/pub512.bin" && ok=1 || ok=0
tap "${ok}" "a stored 32-byte pub does not survive --hash 512" "differs"

"${BIN}" printkey -k "${TMP}/key.hdr" --public-only --out-fmt rawpub >"${TMP}/rawpub.bin"
n=$(wc -c <"${TMP}/rawpub.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 32 ] && echo 1 || echo 0)" "out-fmt rawpub gives a 32-byte pub" "got ${n}"

"${BIN}" printkey --in-fmt rawpub -k "${TMP}/rawpub.bin" --public-only --out-fmt hexpub >"${TMP}/hexpub.hex"
bytes=$(tr -d '\n' <"${TMP}/hexpub.hex" | wc -c | tr -d '[:space:]')
grep -qE '^[0-9a-f]+$' "${TMP}/hexpub.hex" && shape=1 || shape=0
tap "$([ "${bytes}" = 64 ] && [ "${shape}" = 1 ] && echo 1 || echo 0)" "rawpub reads back and hexpub writes hex" "got ${bytes}"

"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" -o "${TMP}/full.hdr"
mode=$(stat -c '%a' "${TMP}/full.hdr" 2>/dev/null || stat -f '%Lp' "${TMP}/full.hdr")
tap "$([ "${mode}" = 600 ] && echo 1 || echo 0)" "full key file is 0600" "got ${mode}"

"${BIN}" printkey --in-fmt raw -k "${TMP}/seed.bin" --public-only -o "${TMP}/pub.hdr"
mode=$(stat -c '%a' "${TMP}/pub.hdr" 2>/dev/null || stat -f '%Lp' "${TMP}/pub.hdr")
tap "$([ "${mode}" = 644 ] && echo 1 || echo 0)" "public-only file is 0644" "got ${mode}"

rc=0
"${BIN}" printkey -k "${TMP}/key.hdr" --out-fmt bogus >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects an unknown format" "exit ${rc}"

rc=0
"${BIN}" printkey >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "requires a key file" "exit ${rc}"

tap_plan
