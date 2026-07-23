//go:build integration && linux && cgo

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package lockwait // import "go.opentelemetry.io/ebpf-profiler/probes/lockwait"

/*
#include <stdint.h>
#include <time.h>

__attribute__((noinline, visibility("default")))
int32_t lock_wait_c_target(uint64_t duration_ns, int32_t result) {
  struct timespec started;
  struct timespec current;
  clock_gettime(CLOCK_MONOTONIC, &started);
  for (;;) {
    clock_gettime(CLOCK_MONOTONIC, &current);
    int64_t elapsed = (int64_t)(current.tv_sec - started.tv_sec) * 1000000000LL;
    elapsed += (int64_t)(current.tv_nsec - started.tv_nsec);
    if (elapsed >= (int64_t)duration_ns) return result;
  }
}

uintptr_t lock_wait_c_target_address(void) {
  return (uintptr_t)&lock_wait_c_target;
}
*/
import "C"

func lockWaitCTargetAddress() uint64 {
	return uint64(C.lock_wait_c_target_address())
}

func callLockWaitCTarget(durationNS uint64) {
	C.lock_wait_c_target(C.uint64_t(durationNS), C.int32_t(-7))
}
