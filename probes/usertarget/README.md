# Process-aware userspace probe targets

`usertarget.Manager` maintains PID-scoped uprobe and uretprobe links from a
runtime descriptor. It does not contain application or library symbol names.

A descriptor selects:

- an exact process name and/or executable path;
- an exact mapped-object basename, path, and/or GNU build ID;
- bounded symbol candidates and/or build-ID-scoped executable file offsets;
- a maximum number of live kernel links.

Example shape:

```yaml
name: service_lock
process:
  executable_name: service
object:
  basename: service
  build_id: 0123456789abcdef # optional for symbols
symbol_candidates:
  - _ZN7service4LockEv
offsets:
  - build_id: 0123456789abcdef
    file_offset: 0x1234
max_links: 1024
```

`executable_name` is `/proc/<pid>/comm` and can be changed by the process.
For untrusted workloads, combine an executable path and/or object build ID
instead of treating the name alone as an identity boundary.

Mapped files are opened through `/proc/<pid>/map_files`; when the kernel
restricts that interface, the process root path is accepted only after a fresh
maps scan still contains the full VMA tuple and its inode/device match. Process
identity is rechecked while attaching. Attachments use the verified open file
through `/proc/self/fd/<fd>` and `link.UprobeOptions.PID`.

Return links are attached before entry links. Symbol aliases resolving to the
same executable file offset are deduplicated. Process exit, exec, PID reuse,
unmap, and manager shutdown remove links in entry-before-return order. Mapping
changes are reconciled when ProcessManager observes a new process, unknown PC,
exec, or exit; this is not a dynamic-loader hook. Exec/exit invalidation can
cancel slow resolution concurrently, and replacement snapshots wait for that
cleanup before attachment. Once `max_links` is saturated, unmatched candidates
are not retained or ELF-resolved; they become eligible on a later mapping event
after capacity is freed. The link bound and LRU/bounded state in individual
probes are independent safety limits.

The manager supports Linux 5.10 and does not depend on attach cookies or
`uprobe_multi`.
