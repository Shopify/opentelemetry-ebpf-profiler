#!/usr/bin/env bash
set -euo pipefail
root=/captures/arm64
binary=/audit/results/a68e42cf-yjit-zjit-aarch64/ruby
mkdir -p "$root/sysroot"
for mode in interpreted yjit zjit; do
  dir="$root/$mode"
  mkdir -p "$dir"
  case "$mode" in
    interpreted) flags=(--disable-yjit --disable-zjit) ;;
    yjit) flags=(--yjit --yjit-call-threshold=10) ;;
    zjit) flags=(--zjit --zjit-call-threshold=10 --zjit-num-profiles=2) ;;
  esac
  ready="$dir/jit-stats-$(date +%s%N).txt"
  "$binary" "${flags[@]}" /audit/fixtures/ruby41.rb "$ready" > "$dir/workload.log" 2>&1 &
  pid=$!
  trap 'kill -TERM "$pid" 2>/dev/null || true' EXIT
  for attempt in $(seq 1 100); do
    test -s "$ready" && break
    kill -0 "$pid"
    sleep 0.1
  done
  test -s "$ready"
  cp "$ready" "$dir/jit-stats.txt"
  printf '0x3f\n' > "/proc/$pid/coredump_filter"
  cp "/proc/$pid/maps" "$dir/maps.txt"
  awk '$6 ~ /^\// {print $6}' "$dir/maps.txt" | sort -u | while read -r file; do
    test -f "$file" && cp -L --parents "$file" "$root/sysroot/"
  done
  gdb -batch -nx -iex 'set auto-load safe-path /nonexistent' -p "$pid" \
    -ex 'set pagination off' -ex 'info threads' -ex 'bt 12' \
    -ex 'p ruby_current_ec->cfp' -ex 'p *ruby_current_ec->cfp' \
    -ex 'p rb_zjit_entry' -ex "gcore $dir/core" -ex 'detach' -ex 'quit' \
    > "$dir/gdb.log" 2>&1
  test -s "$dir/core"
  kill -TERM "$pid"
  wait "$pid" || true
  trap - EXIT
  printf 'Captured %s %s\n' "$mode" "$(date -u +%FT%TZ)"
done
