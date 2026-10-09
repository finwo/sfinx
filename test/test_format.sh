#!/bin/sh
# Pins the wire layout E4M4(N) | path | E4M4(L) | data against committed vectors.
# Fixed inputs: seed 00..1f, message "sfinx golden vector", paths 0a (N1) and 0a1b (N2).
# Regenerating the vectors is documented in PLAN.md (Testing, Golden vectors).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")
TMP=$(mktemp -d)
trap 'rm -rf "${TMP}"' EXIT

V="${ROOT}/test/vectors"

tap_begin "cli: wire format"

missing=""
for f in seed.bin sig-L28-N0.hex sig-L28-N1.hex sig-L32-N0.hex sig-L32-N1.hex sig-L32-N2.hex \
  sig-L48-N0.hex sig-L48-N1.hex sig-L64-N0.hex sig-L64-N1.hex; do
  [ -f "${V}/${f}" ] || missing="${missing} ${f}"
done
tap "$([ -z "${missing}" ] && echo 1 || echo 0)" "all vectors present" "missing:${missing}"

sign_hex() {
  # sign_hex <bits> <path|single>
  if [ "$2" = single ]; then
    "${BIN}" sign --key-fmt raw -k "${V}/seed.bin" -L "$1" --single -m 'sfinx golden vector' --sig-fmt hex
  else
    "${BIN}" sign --key-fmt raw -k "${V}/seed.bin" -L "$1" -P "$2" -m 'sfinx golden vector' --sig-fmt hex
  fi
}

check_vector() {
  # check_vector <bits> <path|single> <L> <N> <bytes>
  got=$(sign_hex "$1" "$2")
  if printf '%s\n' "${got}" | cmp -s - "${V}/sig-L$3-N$4.hex"; then ok=1; else ok=0; fi
  tap "${ok}" "vector L$3 N$4 bytes match" "differs from sig-L$3-N$4.hex"
  n=$(printf '%s' "${got}" | wc -c | tr -d '[:space:]')
  tap "$([ "${n}" = "$(( $5 * 2 ))" ] && echo 1 || echo 0)" "vector L$3 N$4 hex length" "got ${n} want $(( $5 * 2 ))"
}

check_vector 224 single 28 0 842
check_vector 224 0a     28 1 1067
check_vector 256 single 32 0 1090
check_vector 256 0a     32 1 1347
check_vector 256 0a1b   32 2 2692
check_vector 384 single 48 0 2402
check_vector 384 0a     48 1 2787
check_vector 512 single 64 0 4226
check_vector 512 0a     64 1 4739

# Derive the public halves the vectors must verify against
for L in 28 32 48 64; do
  bits=$((L * 8))
  "${BIN}" printkey --in-fmt raw -k "${V}/seed.bin" -L $bits --public-only --out-fmt rawpub -o "${TMP}/pub-$L.bin"
  "${BIN}" printkey --in-fmt raw -k "${V}/seed.bin" -L $bits --single --public-only --out-fmt rawpub \
    -o "${TMP}/pub0-$L.bin"
done

# The hex decoder wants bare hex, strip the vectors' trailing newline
tr -d '\n' <"${V}/sig-L32-N1.hex" >"${TMP}/v-L32-N1.hex"
tr -d '\n' <"${V}/sig-L32-N0.hex" >"${TMP}/v-L32-N0.hex"

"${BIN}" verify --key-fmt rawpub -k "${TMP}/pub-32.bin" -m 'sfinx golden vector' --sig-fmt hex \
  -S "${TMP}/v-L32-N1.hex" >/dev/null && ok=1 || ok=0
tap "${ok}" "committed tree vector verifies" "failed"

"${BIN}" verify --key-fmt rawpub -k "${TMP}/pub0-32.bin" -m 'sfinx golden vector' --sig-fmt hex \
  -S "${TMP}/v-L32-N0.hex" >/dev/null && ok=1 || ok=0
tap "${ok}" "committed single vector verifies" "failed"

# Raw signature is the same bytes, check the byte count too
"${BIN}" sign --key-fmt raw -k "${V}/seed.bin" -L 256 -P 0a -m 'sfinx golden vector' --sig-fmt raw \
  -o "${TMP}/sig-raw.bin"
n=$(wc -c <"${TMP}/sig-raw.bin" | tr -d '[:space:]')
tap "$([ "${n}" = 1347 ] && echo 1 || echo 0)" "raw N1 signature is 1347 bytes" "got ${n}"

patch_byte() {
  # patch_byte <file> <offset> <decimal>
  printf "\\$(printf '%03o' "$3")" | dd of="$1" bs=1 seek="$2" count=1 conv=notrunc 2>/dev/null
}

verify_raw() {
  # verify_raw <pub> <sig>
  "${BIN}" verify --key-fmt rawpub -k "$1" -m 'sfinx golden vector' -S "$2" >/dev/null 2>&1
}

head -c 1346 "${TMP}/sig-raw.bin" >"${TMP}/short.bin"
rc=0
verify_raw "${TMP}/pub-32.bin" "${TMP}/short.bin" || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "a truncated signature fails" "exit ${rc}"

cp "${TMP}/sig-raw.bin" "${TMP}/bad-n.bin"
patch_byte "${TMP}/bad-n.bin" 0 2
rc=0
verify_raw "${TMP}/pub-32.bin" "${TMP}/bad-n.bin" || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "a patched N fails" "exit ${rc}"

cp "${TMP}/sig-raw.bin" "${TMP}/bad-path.bin"
patch_byte "${TMP}/bad-path.bin" 1 11
rc=0
verify_raw "${TMP}/pub-32.bin" "${TMP}/bad-path.bin" || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "a patched path byte fails" "exit ${rc}"

tap_plan
