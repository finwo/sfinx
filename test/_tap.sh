# TAP helpers, source with `. test/_tap.sh`
# Mirrors test/_tap.c: tap_begin, tap, tap_check, tap_plan.

TAP_NO=0
TAP_FAIL=0

tap_begin() {
  TAP_NO=0
  TAP_FAIL=0
  printf 'TAP version 13\n'
  printf '# %s\n' "$1"
}

tap() {
  # tap <ok> <desc> <diag>
  TAP_NO=$((TAP_NO + 1))
  if [ "$1" = 1 ]; then
    printf 'ok %s - %s\n' "${TAP_NO}" "$2"
    return 0
  fi
  TAP_FAIL=$((TAP_FAIL + 1))
  printf 'not ok %s - %s\n' "${TAP_NO}" "$2"
  if [ -n "${3:-}" ]; then
    printf '# %s\n' "$3"
  fi
  return 0
}

tap_check() {
  # tap_check <rc> <desc> <diag>
  if [ "$1" = 0 ]; then
    tap 1 "$2" ""
  else
    tap 0 "$2" "$3"
  fi
}

tap_plan() {
  printf '1..%s\n' "${TAP_NO}"
  if [ "${TAP_FAIL}" -gt 0 ]; then
    printf '# %s of %s assertions failed\n' "${TAP_FAIL}" "${TAP_NO}"
    return 1
  fi
  return 0
}

# Path to the built sfinx binary, building it once on demand
ensure_bin() {
  _root=$1
  _target=$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)
  _bin="${_root}/build/${_target}/sfinx"
  if [ ! -x "${_bin}" ]; then
    (cd "${_root}" && make) >/dev/null 2>&1 || true
  fi
  printf '%s\n' "${_bin}"
}
