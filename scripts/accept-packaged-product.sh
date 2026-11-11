#!/usr/bin/env bash
# Exercise only extracted product and runtime bytes, never the build tree.
set -euo pipefail

[[ $# == 1 ]] || { printf 'Usage: %s PACKAGE_DIRECTORY\n' "$0" >&2; exit 2; }
package_directory="$(cd -- "$1" && pwd)"
shopt -s nullglob
products=("$package_directory"/silo-[0-9]*.tar.zst)
runtimes=("$package_directory"/silo-runtime-*.tar.zst)
[[ ${#products[@]} == 1 && ${#runtimes[@]} == 1 ]] || {
  printf 'Expected one product archive and one runtime archive in %s\n' "$package_directory" >&2
  exit 1
}

# Keep Unix socket paths short, including on macOS.
work="$(mktemp -d /tmp/silo-accept.XXXXXX)"
daemon_pid=""
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$daemon_pid" ]]; then
    kill -KILL "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
  if ((result != 0)); then
    for log in "$work/daemon.log" "$work/status.json"; do
      [[ ! -f "$log" ]] || cat "$log" >&2
    done
  fi
  rm -rf -- "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 700 "$work/product" "$work/runtime" "$work/home" "$work/state" "$work/config" "$work/run"
tar --use-compress-program=unzstd -xf "${products[0]}" --strip-components=1 -C "$work/product"
tar --use-compress-program=unzstd -xf "${runtimes[0]}" --strip-components=1 -C "$work/runtime"
[[ -f "$work/product/share/licenses/tsgate/modules.json" ]]

packaged() {
  env -i PATH="$PATH" HOME="$work/home" SILO_HOME="$work/state" \
    XDG_CONFIG_HOME="$work/config" SILO_RUN_ROOT="$work/run" \
    SILO_RUNTIME_DIR="$work/runtime" NO_COLOR=1 "$@"
}
cli() {
  packaged python3 -c 'import subprocess, sys; sys.exit(subprocess.run(sys.argv[1:], timeout=5).returncode)' \
    "$work/product/bin/silo" "$@"
}
cli --help >/dev/null
packaged "$work/product/bin/tsgate" version
# Not via packaged(): a backgrounded function runs in a subshell, so $! would
# name the subshell instead of the daemon env execs into.
env -i PATH="$PATH" HOME="$work/home" SILO_HOME="$work/state" \
  XDG_CONFIG_HOME="$work/config" SILO_RUN_ROOT="$work/run" \
  SILO_RUNTIME_DIR="$work/runtime" NO_COLOR=1 \
  "$work/product/bin/silo" daemon run --system-enabled=false --tailscale-enabled=false >"$work/daemon.log" 2>&1 &
daemon_pid=$!
ready=false
for ((attempt = 0; attempt < 30; attempt++)); do
  kill -0 "$daemon_pid" 2>/dev/null || { printf 'Packaged daemon exited before readiness\n' >&2; exit 1; }
  if cli daemon status --format json >"$work/status.json" 2>/dev/null &&
    python3 -c 'import json, sys; s=json.load(sys.stdin); sys.exit(not (s["state"] == "ready" and s["daemon"]["pid"] == int(sys.argv[1])))' "$daemon_pid" <"$work/status.json"; then
    ready=true
    break
  fi
  sleep 0.2
done
[[ "$ready" == true ]] || { printf 'Packaged daemon did not become ready\n' >&2; exit 1; }
cat "$work/status.json"
kill -TERM "$daemon_pid"
for ((attempt = 0; attempt < 50; attempt++)); do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    wait "$daemon_pid"
    daemon_pid=""
    printf 'Packaged product acceptance passed\n'
    exit 0
  fi
  sleep 0.2
done
printf 'Packaged daemon did not stop within 10 seconds\n' >&2
exit 1
