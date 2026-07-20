// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package memory

import "fmt"

func newAllocatorInjector(_ string, mode InjectionMode, _ uint64, _ bool) (allocatorInjector, error) {
	return nil, fmt.Errorf("experimental allocator injection mode %q is only implemented on linux/amd64", mode)
}
