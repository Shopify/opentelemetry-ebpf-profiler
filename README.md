# Ruby 4.1.0dev coredump test data

Packed coredump-store objects for the Ruby 4.1.0dev `TestCoreDumps` cases on branch
`dale/ruby41-coredump-fixtures` (commit `936f8a917be7`) of `Shopify/opentelemetry-ebpf-profiler`.
That branch is stacked on #85 (ZJIT frames), which is stacked on #84 (Ruby 4.1 layout).

This isolated data branch keeps about 112 MB of binary test data out of the PRs' review history
until the objects are published to the canonical coredump store. The files here let reviewers and
maintainers replay the fixtures without store access.

## Contents

- `module-store/<id>`: 28 objects, already in the coredump tool's **zstpak** format.
  - 12 are cores; the other 16 are the Ruby binary and the shared libraries each core maps.
  - IDs are content hashes of the original files. For example, a case's `coredump-ref` is the SHA-256 of its raw core.
  - Copy them into `tools/coredump/modulecache/` as-is. Do not decompress or rename them.
- `testdata/{arm64,amd64}/ruby-4.1.0-a68e42cf-*.json`: the 20 fixtures, byte-identical to the fixtures branch.
- `manifest.json` lists every case and the objects it references.
  - `manifest-layout.json`: the 12 layout cases, 6 per architecture (interpreted, YJIT native call, YJIT loop, GC).
  - `manifest-zjit.json`: the 8 ZJIT cases, 4 per architecture.
- `SHA256SUMS`: transport checksums for every other file in this branch.
- `provenance/`: the scripts used to build the binary and capture the cores.

## Provenance

- **Ruby**: [Shopify/ruby@`a68e42cf`](https://github.com/Shopify/ruby/commit/a68e42cfad16857e146d27044c9116cd4bae950b), built from source.
  - Static `miniruby`, installed as `ruby`, with YJIT and ZJIT both configured.
  - `-O0 -g3 -gdwarf-4`, frame pointers kept, Rust 1.90, Ubuntu 24.04 userland.
  - These are debug builds, not optimized release builds.
- **arm64**: built and captured natively in an Ubuntu 24.04 container on an arm64 Linux 6.8 VM.
- **amd64**: built in an amd64 container under QEMU user emulation. Captured under a real x86_64 Linux 6.8 kernel (Ubuntu 24.04) in a full-system QEMU VM (`provenance/ruby41-amd64.lima.yaml`).
- **Workloads**: synthetic scripts from `tools/coredump/testsources/ruby/ruby41*.rb`. No application code or data.
- **Capture**: `gdb` attach plus `gcore`, with `coredump_filter` set to `0x3f`, while the process kept running.
  - JIT cases were captured only after `RubyVM::YJIT` / `RubyVM::ZJIT` statistics showed compiled code.
  - The GC core was stopped in `gc_marks` after `GC.start`.
- **Contents of the cores**: only the synthetic processes' memory.
  - The process environments include container hostnames and `USER=root`.
  - The amd64 cores also include the capturing account's `SUDO_USER`.
  - All cores were scanned for credentials and tokens before publishing.

## Replay

`TestCoreDumps` replays a case only on a host of the same architecture.

```sh
data=$(mktemp -d)
git clone --depth 1 --single-branch --branch dale/ruby41-coredump-data \
  https://github.com/Shopify/opentelemetry-ebpf-profiler.git "$data"
(cd "$data" && shasum -a 256 -c SHA256SUMS)

# In a checkout of dale/ruby41-coredump-fixtures:
mkdir -p tools/coredump/modulecache
cp "$data"/module-store/* tools/coredump/modulecache/
(cd tools/coredump && go test -run 'TestCoreDumps/testdata/(amd64|arm64)/ruby-4.1.0-a68e42cf-' .)
```

Individual objects are also available at commit-pinned raw URLs,
`https://raw.githubusercontent.com/Shopify/opentelemetry-ebpf-profiler/<commit>/module-store/<id>`,
where `<commit>` is this branch's commit.
