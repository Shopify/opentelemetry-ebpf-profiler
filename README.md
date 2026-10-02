# Ruby GC layout coredump data for #1934

This artifact branch contains packed coredump test objects for
[open-telemetry/opentelemetry-ebpf-profiler#1934](https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/1934).
These are not raw cores.

## Contents

- `module-store/<id>`: 99 existing zstpak module-store objects, copied byte-for-byte from the coredump tool's `modulecache`. Upload them unchanged. The filename is the SHA-256 of the raw object; `manifest.json` also records the SHA-256 of the packed file.
- `testdata/{arm64,amd64}`: 14 regression fixtures, seven per architecture.
- `diagnostics/{arm64,amd64}`: six replay configs. These cover default Ruby 3.3 native-resume behavior and the reporter's nested `Array#each` workload, and are not proposed as regression goldens.
- `workloads/`: the original issue loop, the GC marking workload, and the exact follow-up script from the reporter.
- `provenance.json`: pinned image digests, raw core IDs, GDB-confirmed Ruby versions, GC state, objspace offsets, and sanitized process environments.
- `publication-scan.json`: results of a targeted scan of the 16 raw cores and all referenced raw ELFs for private keys, common token formats, credential environment variables, and private local identity/path strings. The scan had zero findings.

## Capture method

All workloads used the official Docker `ruby` images, pinned by digest in `provenance.json`. Each target process ran with only:

```text
PATH=/usr/local/bin:/usr/bin:/bin
HOME=/root
LANG=C.UTF-8
```

arm64 workloads ran in native arm64 Docker containers with networking disabled. amd64 workloads ran from the exact exported image root filesystem, in a chroot under an x86_64 Linux kernel running on QEMU/TCG (full-system emulation, not QEMU-user). GDB checked each running process's Ruby version and `rb_objspace.flags` before writing the core.

The regression fixtures cover the 3.2.2 baseline, the 3.2.3 and 3.2.4 layout boundaries, 3.2.11 GC and non-GC stacks, and Ruby 3.3.12 GC on both architectures.

Ruby 3.3 sampled in `Process.clock_gettime` is a separate native-resume issue. The committed 3.3 loop golden explicitly sets `skip_native_resume`. Diagnostic configs keep the default-mode output separate.

## Local replay

Copy the objects directly into a profiler checkout:

```bash
mkdir -p tools/coredump/modulecache
cp module-store/* tools/coredump/modulecache/
cp testdata/arm64/*.json tools/coredump/testdata/arm64/
cp testdata/amd64/*.json tools/coredump/testdata/amd64/
cd tools/coredump
go test -run 'TestCoreDumps/testdata/(arm64|amd64)/ruby-.*-docker-' -v
```

Run each architecture's cases on a matching host or VM.
