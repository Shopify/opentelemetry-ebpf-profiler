#!/usr/bin/env bash
# Combined JIT build of the exact deployed Shopify/ruby revision.
set -euo pipefail
revision=a68e42cfad16857e146d27044c9116cd4bae950b
arch=$(uname -m)
case "$arch" in aarch64|x86_64) ;; *) exit 1;; esac
work=/work/ruby-a68e42cf-yjit-zjit
result=/audit/results/a68e42cf-yjit-zjit-${arch}
mkdir -p "$work" "$result" /work/rust-installer
exec > >(tee "$result/build.log") 2>&1
printf 'Start combined JIT %s %s %s\n' "$revision" "$arch" "$(date -u +%FT%TZ)"
if [[ ! -x /opt/rust-1.90.0/bin/rustc || ! -d /opt/rust-1.90.0/lib/rustlib/${arch}-unknown-linux-gnu/lib ]]; then
  for component in rustc rust-std; do
    package="${component}-1.90.0-${arch}-unknown-linux-gnu"
    (cd /audit/toolchains && sha256sum -c "${package}.tar.xz.sha256")
    tar -xJf "/audit/toolchains/${package}.tar.xz" -C /work/rust-installer
    bash "/work/rust-installer/${package}/install.sh" --prefix=/opt/rust-1.90.0 --disable-ldconfig >> "$result/rust-install.log" 2>&1
  done
fi
export PATH=/opt/rust-1.90.0/bin:$PATH
if [[ "$arch" == x86_64 ]]; then
  export QEMU_GUEST_BASE=0x800000000000 RUST_MIN_STACK=16777216
fi
{ uname -a; gcc --version; gcc -dumpmachine; rustc --version; gdb --version; pahole --version; ruby --version; } > "$result/toolchain.txt"
sha256sum /audit/ruby-a68e42cf.tar.gz > "$result/source.sha256"
tar -xzf /audit/ruby-a68e42cf.tar.gz --strip-components=1 -C "$work"
cd "$work"
python3 - "$revision" <<'PY'
import datetime, pathlib, sys
r = sys.argv[1]
n = datetime.datetime.now(datetime.timezone.utc)
pathlib.Path('revision.h').write_text('\n'.join([
    f'#define RUBY_REVISION "{r[:10]}"', f'#define RUBY_FULL_REVISION "{r}"',
    '#define RUBY_BRANCH_NAME "shopify"',
    f'#define RUBY_RELEASE_DATETIME "{n.strftime("%Y-%m-%dT%H:%M:%SZ")}"',
    f'#define RUBY_RELEASE_YEAR {n.year}', f'#define RUBY_RELEASE_MONTH {n.month}',
    f'#define RUBY_RELEASE_DAY {n.day}',
]) + '\n')
PY
cp revision.h "$result/revision.h"
./autogen.sh > "$result/autogen.log" 2>&1
./configure --disable-install-doc --disable-shared --enable-yjit --enable-zjit \
  --prefix=/opt/ruby/a68e42cf-yjit-zjit \
  optflags=-O0 debugflags='-g3 -gdwarf-4 -fno-eliminate-unused-debug-types' \
  cflags=-fno-omit-frame-pointer > "$result/configure.log" 2>&1
printf 'Configured combined JIT %s %s\n' "$arch" "$(date -u +%FT%TZ)"
make -j3 miniruby > "$result/make.log" 2>&1
./miniruby --zjit -v > "$result/version.txt"
./miniruby --zjit --zjit-call-threshold=10 --zjit-num-profiles=2 -e '
  abort "wrong source revision" unless RUBY_REVISION == "a68e42cfad16857e146d27044c9116cd4bae950b"
  abort "ZJIT is not enabled" unless RubyVM::ZJIT.enabled?
  abort "YJIT unexpectedly enabled" if RubyVM::YJIT.enabled?
  def audit_sum(n)
    (1..n).inject(0) { |a, b| a + b }
  end
  200.times { abort "wrong result" unless audit_sum(100) == 5050 }
  stats = RubyVM::ZJIT.stats
  abort "no ZJIT compilation" unless stats[:compiled_iseq_count] > 0
  puts "revision=#{RUBY_REVISION}"
  puts "zjit_enabled=#{RubyVM::ZJIT.enabled?}"
  p stats
' > "$result/runtime-smoke-zjit.txt" 2>&1
./miniruby --yjit --yjit-call-threshold=2 -e '
  abort "YJIT is not enabled" unless RubyVM::YJIT.enabled?
  abort "ZJIT unexpectedly enabled" if RubyVM::ZJIT.enabled?
  def audit_sum(n); (1..n).inject(0) { |a, b| a + b }; end
  100.times { abort "wrong result" unless audit_sum(100) == 5050 }
  puts "yjit_enabled=#{RubyVM::YJIT.enabled?}"
  p RubyVM::YJIT.runtime_stats
' > "$result/runtime-smoke-yjit.txt" 2>&1
gdb -batch -nx -iex 'set auto-load safe-path /nonexistent' miniruby \
  -ex 'source /audit/gdb-dump-offsets.py' -ex 'source /audit/gdb-extra-offsets.py' \
  -ex 'source /audit/gdb-zjit-offsets.py' > "$result/gdb.log" 2>&1
python3 - "$result" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
records = [json.loads(line) for line in p.joinpath('gdb.log').read_text().splitlines() if line.startswith('{')]
assert len(records) == 3, len(records)
assert len(records[0]) == 59
for name, record in zip(('offsets', 'extra-offsets-complete', 'zjit-offsets'), records):
    p.joinpath(name + '.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
print(json.dumps(records[2], sort_keys=True))
PY
for struct in rb_vm_struct rb_ractor_struct rb_iseq_constant_body rb_control_frame_struct rb_execution_context_struct rb_thread_struct rb_iseq_struct rb_iseq_location_struct rb_objspace zjit_jit_frame; do
  pahole -C "$struct" miniruby > "$result/${struct}.txt" 2> "$result/${struct}.stderr"
done
cp miniruby "$result/ruby"
cp config.status Makefile "$result/"
cp .ext/include/*/ruby/config.h "$result/config.h"
sha256sum "$result/ruby" > "$result/binary.sha256"
printf 'Completed combined JIT %s %s\n' "$arch" "$(date -u +%FT%TZ)"
