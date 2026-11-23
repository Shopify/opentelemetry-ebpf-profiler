// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import "fmt"

const (
	defaultMapScaleFactor           = 2
	maxMapScaleFactor               = 8
	defaultLiveHeapMaxEntriesPerPID = 10_000
)

// Config configures the heap profiling probe.
type Config struct {
	MapScaleFactor uint `mapstructure:"map_scale_factor"`

	// LiveHeapProfiling additionally loads the free probe so that
	// deallocations can be tracked for live/inuse heap reporting.
	LiveHeapProfiling bool `mapstructure:"live_heap_profiling"`

	// LiveHeapMaxEntriesPerPID is the maximum number of live allocations
	// tracked per process in the eBPF heap_alloc_live map. Allocations
	// beyond this limit are not tracked for inuse profiling. Zero disables
	// per-PID limiting.
	LiveHeapMaxEntriesPerPID int `mapstructure:"live_heap_max_entries_per_pid"`
}

// Validate implements confmap.Validator.
func (c *Config) Validate() error {
	if c.MapScaleFactor > maxMapScaleFactor {
		return fmt.Errorf(
			"heap eBPF map scaling factor %d exceeds limit (max: %d)",
			c.MapScaleFactor, maxMapScaleFactor,
		)
	}
	if c.LiveHeapMaxEntriesPerPID < 0 {
		return fmt.Errorf("heap: live_heap_max_entries_per_pid must not be negative")
	}
	return nil
}
