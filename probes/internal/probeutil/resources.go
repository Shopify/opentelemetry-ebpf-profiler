// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package probeutil contains lifecycle helpers shared by dynamic probes.
package probeutil // import "go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Resources owns probe resources and closes them in reverse creation order.
type Resources struct {
	closers []io.Closer
}

// Add transfers ownership of non-nil closers to Resources.
func (r *Resources) Add(closers ...io.Closer) {
	for _, closer := range closers {
		if closer != nil {
			r.closers = append(r.closers, closer)
		}
	}
}

// WrapLink transfers ownership of primary and returns a link whose Close
// releases all resources. Other Link operations delegate to primary.
func (r *Resources) WrapLink(primary link.Link) link.Link {
	r.Add(primary)
	return &resourceLink{Link: primary, resources: r}
}

type resourceLink struct {
	link.Link
	resources *Resources
}

func (l *resourceLink) Close() error {
	return l.resources.Close()
}

// Close releases every resource, returning all close failures as a joined error.
func (r *Resources) Close() error {
	closers := r.closers
	r.closers = nil
	var errs []error
	for i := len(closers) - 1; i >= 0; i-- {
		if err := closers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// LoadMaps loads the named probe-private maps from a collection specification.
func LoadMaps(spec *ebpf.CollectionSpec, names []string,
	resources *Resources) (map[string]*ebpf.Map, error) {
	maps := make(map[string]*ebpf.Map, len(names))
	for _, name := range names {
		mapSpec, ok := spec.Maps[name]
		if !ok {
			return nil, fmt.Errorf("map %q is unavailable", name)
		}
		loaded, err := ebpf.NewMap(mapSpec)
		if err != nil {
			return nil, fmt.Errorf("failed to load map %q: %w", name, err)
		}
		maps[name] = loaded
		resources.Add(loaded)
	}
	return maps, nil
}
