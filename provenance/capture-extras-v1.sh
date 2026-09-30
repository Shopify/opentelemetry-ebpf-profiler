#!/usr/bin/env bash
set -euo pipefail
arch=$(uname -m)
case "$arch" in aarch64) goarch=arm64;; x86_64) goarch=amd64;; *) exit 1;; esac
root=/var/tmp/ruby41-extra-captures/$goarch
binary=/audit/results/a68e42cf-yjit-zjit-${arch}/ruby
mkdir -p "$root/sysroot"
for mode in yjit zjit; do
  dir="$root/$mode-loop"
  mkdir -p "$dir"
  flags=(--yjit --yjit-call-threshold=10)
  test "$mode" != zjit || flags=(--zjit --zjit-call-threshold=10 --zjit-num-profiles=2)
  ready="$dir/ready-$(date +%s%N).txt"
  "$binary" "${flags[@]}" /audit/fixtures/ruby41-busy.rb "$ready" > "$dir/workload.log" 2>&1 &
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
    -ex 'set pagination off' -ex 'p/x $pc' -ex 'bt 8' \
    -ex 'p ruby_current_ec->cfp' -ex 'p *ruby_current_ec->cfp' \
    -ex 'p rb_zjit_entry' -ex "gcore $dir/core" -ex 'detach' -ex 'quit' \
    > "$dir/gdb.log" 2>&1
  test -s "$dir/core"
  kill -TERM "$pid"
  wait "$pid" || true
  trap - EXIT
  printf 'Captured %s %s-loop %s\n' "$goarch" "$mode" "$(date -u +%FT%TZ)"
done
dir="$root/gc"
mkdir -p "$dir"
gdb -batch -nx -iex 'set auto-load safe-path /nonexistent' "$binary" \
  -ex 'set pagination off' \
  -ex 'set args --disable-yjit --disable-zjit /audit/fixtures/ruby41-gc.rb' \
  -ex 'break gc_start_internal' -ex 'run' -ex 'break gc_marks' -ex 'continue' \
  -ex 'bt 12' -ex 'p objspace->flags' \
  -ex 'p/x *(unsigned int *)((char *)objspace + 76)' \
  -ex 'python open("/proc/%d/coredump_filter" % gdb.selected_inferior().pid, "w").write("0x3f")' \
  -ex "gcore $dir/core" -ex 'quit' > "$dir/gdb.log" 2>&1
test -s "$dir/core"
printf 'Captured %s GC %s\n' "$goarch" "$(date -u +%FT%TZ)"
cp -R "$root" "/audit/cores/$goarch-extras-v1"
