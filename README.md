# LuaJIT coredump test data (backup)

Compressed live coredumps captured from the GC64 tarantool **fib/churn** test
workload on staging, for building `tools/coredump` LuaJIT regression tests.

This is a **temporary backup branch** until the cores are uploaded to the
coredump module store (OCI `ebpf-profiling-coredumps`, via the drive-folder
upload). The `coredump new` test cases live on the LuaJIT branches (#49); these
are the raw cores they were/will be built from.

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
`cores/core.tarantool-arm64-jitoff.gz` — captured with `jit.off(true,true)` (interpreter
execution). This is the core behind the committed `testdata/arm64/luajit-tarantool-arm64.json`
(skipped pending upload). Regenerate the test + module bundle deterministically with:
`coredump new -core <core> -sysroot <tarantool+libs> -luajit-executables tarantool -name luajit-tarantool-arm64`,
then `coredump upload -all` and remove the test's `skip`.
