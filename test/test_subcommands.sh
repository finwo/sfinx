#!/bin/sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "${HERE}/.." && pwd)
. "${HERE}/_tap.sh"

BIN=$(ensure_bin "${ROOT}")

tap_begin "cli: subcommands"

out=$("${BIN}" --help 2>&1 || true)
case "${out}" in *"usage: sfinx"*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "--help shows usage" "${out}"

out=$("${BIN}" help 2>&1 || true)
case "${out}" in *seed*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "help lists seed" "${out}"
case "${out}" in *generate*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "help lists generate" "${out}"
case "${out}" in *printkey*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "help lists printkey" "${out}"
case "${out}" in *sign*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "help lists sign" "${out}"
case "${out}" in *verify*) ok=1 ;; *) ok=0 ;; esac
tap "${ok}" "help lists verify" "${out}"

out=$("${BIN}" --version 2>&1 || true)
tap "$([ -n "${out}" ] && echo 1 || echo 0)" "--version prints" "empty"

out=$("${BIN}" version 2>&1 || true)
tap "$([ -n "${out}" ] && echo 1 || echo 0)" "version command prints" "empty"

rc=0
"${BIN}" nope >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "unknown command fails" "exit ${rc}"

rc=0
"${BIN}" >/dev/null 2>&1 || rc=$?
tap "$([ "${rc}" != 0 ] && echo 1 || echo 0)" "no args fails" "exit ${rc}"

tap_plan
