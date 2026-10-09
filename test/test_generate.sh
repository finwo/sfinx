#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

bytes() {
  wc -c <"$1" | tr -d '[:space:]'
}

tap_begin "cli: generate"

"${BIN}" generate -o "${TMP}/a.hdr"
grep -q '^seed: ' "${TMP}/a.hdr" && grep -q '^public-key: ' "${TMP}/a.hdr" && ok=1 || ok=0
tap "${ok}" "hdr writes one combined file" "$(cat "${TMP}/a.hdr")"
tap "$([ ! -e "${TMP}/a.hdr.pub" ] && echo 1 || echo 0)" "hdr creates no pub file" "a.hdr.pub exists"
tap "$([ "$(mode "${TMP}/a.hdr")" = 600 ] && echo 1 || echo 0)" "hdr key file is 0600" "got $(mode "${TMP}/a.hdr")"

"${BIN}" generate >"${TMP}/stdout.hdr"
grep -q '^seed: ' "${TMP}/stdout.hdr" && grep -q '^public-key: ' "${TMP}/stdout.hdr" && ok=1 || ok=0
tap "${ok}" "hdr to stdout is the combined file" "$(cat "${TMP}/stdout.hdr")"

"${BIN}" generate --out-fmt raw -o "${TMP}/b.key"
tap "$([ "$(bytes "${TMP}/b.key")" = 32 ] && echo 1 || echo 0)" "raw key holds a 32-byte seed" "got $(bytes "${TMP}/b.key")"
tap "$([ "$(bytes "${TMP}/b.pub")" = 32 ] && echo 1 || echo 0)" "raw pub holds a 32-byte public key" "got $(bytes "${TMP}/b.pub")"
tap "$([ ! -e "${TMP}/b.key.pub" ] && echo 1 || echo 0)" "the .key suffix is replaced, not appended to" "b.key.pub exists"
tap "$([ "$(mode "${TMP}/b.key")" = 600 ] && [ "$(mode "${TMP}/b.pub")" = 644 ] && echo 1 || echo 0)" \
  "raw pair is 0600 and 0644" "$(mode "${TMP}/b.key") $(mode "${TMP}/b.pub")"

"${BIN}" generate --out-fmt raw -o "${TMP}/c.KEY"
tap "$([ -e "${TMP}/c.PUB" ] && echo 1 || echo 0)" ".KEY becomes .PUB" "$(ls -1 "${TMP}")"
"${BIN}" generate --out-fmt raw -o "${TMP}/d.Key"
tap "$([ -e "${TMP}/d.Pub" ] && echo 1 || echo 0)" ".Key becomes .Pub" "$(ls -1 "${TMP}")"
"${BIN}" generate --out-fmt hex -o "${TMP}/e.hex"
tap "$([ -e "${TMP}/e.hex.pub" ] && echo 1 || echo 0)" "a suffix that is not .key has .pub appended" "$(ls -1 "${TMP}")"

grep -qE '^[0-9a-f]{64}$' "${TMP}/e.hex" && ok=1 || ok=0
tap "${ok}" "hex key file is 64 hex characters" "$(cat "${TMP}/e.hex")"
grep -qE '^[0-9a-f]{64}$' "${TMP}/e.hex.pub" && ok=1 || ok=0
tap "${ok}" "hex pub file is 64 hex characters" "$(cat "${TMP}/e.hex.pub")"

"${BIN}" generate --out-fmt raw >"${TMP}/out.raw"
tap "$([ "$(bytes "${TMP}/out.raw")" = 32 ] && echo 1 || echo 0)" "raw stdout is seed only" "got $(bytes "${TMP}/out.raw")"

"${BIN}" generate --out-fmt hex >"${TMP}/out.hex"
tap "$([ "$(bytes "${TMP}/out.hex")" = 64 ] && echo 1 || echo 0)" "hex stdout is seed only" "got $(bytes "${TMP}/out.hex")"

"${BIN}" generate 16 --out-fmt raw -o "${TMP}/s.key"
tap "$([ "$(bytes "${TMP}/s.key")" = 16 ] && echo 1 || echo 0)" "a length argument sizes the seed" "got $(bytes "${TMP}/s.key")"

"${BIN}" generate -L 512 --out-fmt raw -o "${TMP}/h.key"
tap "$([ "$(bytes "${TMP}/h.pub")" = 64 ] && echo 1 || echo 0)" "--hash 512 gives a 64-byte pub" "got $(bytes "${TMP}/h.pub")"

"${BIN}" printkey --in-fmt raw -k "${TMP}/b.key" --public-only --out-fmt rawpub >"${TMP}/b.expect"
cmp -s "${TMP}/b.pub" "${TMP}/b.expect" && ok=1 || ok=0
tap "${ok}" "the pub matches printkey for the same seed" "differs"

rc=0
"${BIN}" generate -o "${TMP}/a.hdr" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "refuses an existing key file" "exit ${rc}"

rc=0
"${BIN}" generate -F -o "${TMP}/a.hdr" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" = 0 ] && echo 1 || echo 0)" "--force overwrites" "exit ${rc}"

rm "${TMP}/s.key"
rc=0
"${BIN}" generate --out-fmt raw -o "${TMP}/s.key" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "refuses when only the pub is taken" "exit ${rc}"
tap "$([ ! -e "${TMP}/s.key" ] && echo 1 || echo 0)" "a refused pair writes no key file" "s.key exists"

rc=0
"${BIN}" generate --out-fmt rawpub -o "${TMP}/no.key" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects a pub-only output format" "exit ${rc}"

rc=0
"${BIN}" generate --out-fmt bogus >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects an unknown format" "exit ${rc}"

rc=0
"${BIN}" generate 0 >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects a zero length" "exit ${rc}"

rc=0
"${BIN}" generate abc >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects a non-numeric length" "exit ${rc}"

"${BIN}" generate --out-fmt raw -o "${TMP}/v.key"
"${BIN}" sign -k "${TMP}/v.key" -m hello -P 0011 -o "${TMP}/v.sig"
"${BIN}" verify -k "${TMP}/v.pub" -m hello -S "${TMP}/v.sig" >/dev/null && ok=1 || ok=0
tap "${ok}" "sign with the key, verify with the pub" "failed"

tap_plan
