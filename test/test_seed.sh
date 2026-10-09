#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

tap_begin "cli: seed"

if [ ! -x "${BIN}" ]; then
  tap 0 "sfinx binary present" "missing ${BIN}"
  tap_plan
  exit 1
fi
tap 1 "sfinx binary present" ""

"${BIN}" seed >"${TMP}/default.bin"
n=$(wc -c <"${TMP}/default.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 32 ] && echo 1 || echo 0)" "default is 32 bytes" "got ${n}"

"${BIN}" seed 16 >"${TMP}/sixteen.bin"
n=$(wc -c <"${TMP}/sixteen.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 16 ] && echo 1 || echo 0)" "explicit length is honored" "got ${n}"

"${BIN}" seed 32 >"${TMP}/a.bin"
"${BIN}" seed 32 >"${TMP}/b.bin"
if cmp -s "${TMP}/a.bin" "${TMP}/b.bin"; then
  tap 0 "two seeds differ" "identical"
else
  tap 1 "two seeds differ" ""
fi

"${BIN}" seed -o "${TMP}/out.seed"
mode=$(stat -c '%a' "${TMP}/out.seed" 2>/dev/null || stat -f '%Lp' "${TMP}/out.seed")
tap "$([ "${mode}" = 600 ] && echo 1 || echo 0)" "-o writes mode 0600" "got ${mode}"

rc=0
"${BIN}" seed 0 >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "rejects length 0" "exit ${rc}"

tap_plan
