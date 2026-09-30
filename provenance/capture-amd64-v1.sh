#!/usr/bin/env bash
set -euo pipefail
root=/var/tmp/ruby41-capture-20260929/amd64
binary=/audit/results/a68e42cf-yjit-zjit-x86_64/ruby
mkdir -p "$root/sysroot"
uname -a > "$root/environment.txt"
gdb --version >> "$root/environment.txt"
sha256sum "$binary" >> "$root/environment.txt"
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
  for attempt in $(seq 1 300); do
    test -s "$ready" && break
    kill -0 "$pid"
    sleep 0.1
  done
  test -s "$ready"
  cp "$ready" "$dir/jit-stats.txt"
  printf '0x3f\n' > "/proc/$pid/coredump_filter"
  cp "/proc/$pid/maps" "$dir/maps.txt"
  chmod 644 "$dir/maps.txt"
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
  printf 'Captured amd64 %s %s\n' "$mode" "$(date -u +%FT%TZ)"
done
cp -R "$root" /audit/cores/amd64-complete-v1
