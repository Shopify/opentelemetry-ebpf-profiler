// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/elastic/go-perf"
)

const defaultPerfEventSysfsRoot = "/sys/bus/event_source/devices/cpu"

// readPerfEventAttr resolves a named PMU alias through sysfs. Event aliases and
// format files are the kernel's CPU-model-specific contract; hard-coded raw
// encodings would silently select the wrong event on other processors.
func readPerfEventAttr(root, eventName string) (*perf.Attr, error) {
	typeData, err := os.ReadFile(filepath.Join(root, "type"))
	if err != nil {
		return nil, fmt.Errorf("read PMU type: %w", err)
	}
	eventType, err := strconv.ParseUint(strings.TrimSpace(string(typeData)), 0, 32)
	if err != nil {
		return nil, fmt.Errorf("parse PMU type: %w", err)
	}

	encodingData, err := os.ReadFile(filepath.Join(root, "events", eventName))
	if err != nil {
		return nil, fmt.Errorf("read event %q: %w", eventName, err)
	}

	attr := &perf.Attr{Label: eventName, Type: perf.EventType(eventType)}
	for item := range strings.SplitSeq(strings.TrimSpace(string(encodingData)), ",") {
		key, valueText, ok := strings.Cut(strings.TrimSpace(item), "=")
		key = strings.TrimSpace(key)
		valueText = strings.TrimSpace(valueText)
		if !ok || key == "" || valueText == "" {
			return nil, fmt.Errorf("parse event %q encoding %q", eventName, item)
		}
		value, err := strconv.ParseUint(valueText, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("parse event %q field %q: %w", eventName, key, err)
		}
		formatData, err := os.ReadFile(filepath.Join(root, "format", key))
		if err != nil {
			return nil, fmt.Errorf("read event %q format %q: %w", eventName, key, err)
		}
		if err := applyPerfEventFormat(attr, strings.TrimSpace(string(formatData)), value); err != nil {
			return nil, fmt.Errorf("apply event %q field %q: %w", eventName, key, err)
		}
	}
	return attr, nil
}

func applyPerfEventFormat(attr *perf.Attr, format string, value uint64) error {
	field, bitList, ok := strings.Cut(format, ":")
	if !ok {
		return fmt.Errorf("invalid format %q", format)
	}

	var target *uint64
	switch strings.TrimSpace(field) {
	case "config":
		target = &attr.Config
	case "config1":
		target = &attr.Config1
	case "config2":
		target = &attr.Config2
	default:
		return fmt.Errorf("unsupported perf attribute field %q", field)
	}

	var sourceBit uint
	for part := range strings.SplitSeq(bitList, ",") {
		startText, endText, hasRange := strings.Cut(strings.TrimSpace(part), "-")
		start, err := strconv.ParseUint(startText, 10, 6)
		if err != nil {
			return fmt.Errorf("invalid bit range %q", part)
		}
		end := start
		if hasRange {
			end, err = strconv.ParseUint(endText, 10, 6)
			if err != nil || end < start {
				return fmt.Errorf("invalid bit range %q", part)
			}
		}
		width := uint(end-start) + 1
		if width > 64-sourceBit {
			return fmt.Errorf("bit ranges exceed 64 source bits")
		}
		if width == 64 {
			if sourceBit != 0 {
				return fmt.Errorf("invalid 64-bit range %q", part)
			}
			*target |= value
			sourceBit = 64
			continue
		}
		mask := uint64(1)<<width - 1
		*target |= ((value >> sourceBit) & mask) << uint(start)
		sourceBit += width
	}
	if sourceBit < 64 && value>>sourceBit != 0 {
		return fmt.Errorf("value %#x does not fit format %q", value, format)
	}
	return nil
}
