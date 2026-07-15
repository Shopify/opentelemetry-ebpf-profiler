# LuaJIT coredump test data

Compressed live coredumps captured from the GC64 tarantool **fib/churn** test
workload on staging, plus the pre-packed local-validation bundle for
`parca-dev/opentelemetry-ebpf-profiler#317`.

This isolated data branch keeps large test artifacts out of the PR's review
history while the cores and modules await canonical coredump-store publication.
The `coredump new` test cases live in #317; the files here let maintainers replay
them without artifact-store access.

## Cores
| file | arch | source pod | tarantool build-id |
|------|------|-----------|--------------------|
| `cores/core.tarantool-amd64.gz` | amd64 | `tarantool-gc64-coredump-amd64` (n4 node, staging) | `101a1bc9be823b62357cec759b31ddac7fa430f2` |
| `cores/core.tarantool-arm64.gz` | arm64 | `tarantool-gc64-coredump-arm64` (c4a node, staging) | `81d29008…` |

- Image: `shopkv/tarantool@sha256:cae05783…` (GC64, shopkv#936), workload ConfigMap `lua-workload-gc64` (`fib`/`churn`/`hot_loop`).
- Captured live via `gcore` (coredump_filter `0x3f`, process kept running).
- Matching symbolized binaries: `~/tarantool-dis/tarantool-gc64-{x86,arm64}` (same build-ids), re-extractable from the image.

## Rebuild a test case
```
gunzip -k cores/core.tarantool-arm64.gz
# sysroot = tarantool binary + /usr/lib/<triple> libs from the pod
coredump new -core core.tarantool-arm64 -sysroot <sysroot> \
  -luajit-executables tarantool -name luajit-tarantool-arm64
```

## jit-off interpreter cores (used by the committed tests)

`cores/core.tarantool-{amd64,arm64}-jitoff.gz` were captured with
`jit.off(true,true)` (interpreter execution). They back the unskipped amd64 and
arm64 fixtures in #317. Regenerate a test and module bundle with:

```text
coredump new -core <core> -sysroot <tarantool+libs> \
  -name luajit-tarantool-<arch>
```

## PR #317 replay bundle

`artifacts/parca-tarantool-luajit-pr317.tar` contains the two pre-packed cores
and ten pre-packed modules in the coredump tool's zstpak format, plus manifests
and transport checksums. Copy its `module-store/*` files directly into
`tools/coredump/modulecache/`; do not decompress the individual objects.

Archive SHA-256:

```text
ce9a4e285df58d9eb3cd3706fb851f50bc06011d1c5850eb02848991fe3e1869
```

See the archive's `README.md` and PR #317 for architecture-matched replay
commands.
