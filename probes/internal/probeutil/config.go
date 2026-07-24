// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package probeutil // import "go.opentelemetry.io/ebpf-profiler/probes/internal/probeutil"

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// LatencyConfig is the common configuration for correlated latency probes.
type LatencyConfig struct {
	MinDuration     time.Duration
	SampleThreshold uint32
	MaxEntries      uint32
}

// ParseLatencyConfig parses min_duration, sample_rate, and max_entries.
func ParseLatencyConfig(raw any, kind string, defaultMaxEntries, maximumMaxEntries uint32) (
	LatencyConfig, error,
) {
	cfg, err := configMap(raw, kind)
	if err != nil {
		return LatencyConfig{}, err
	}
	for key := range cfg {
		switch key {
		case "min_duration", "sample_rate", "max_entries":
		default:
			return LatencyConfig{}, fmt.Errorf("unknown %s configuration field %q", kind, key)
		}
	}

	minDuration, err := durationValue(cfg, "min_duration", 0)
	if err != nil {
		return LatencyConfig{}, err
	}
	if minDuration < 0 {
		return LatencyConfig{}, errors.New("min_duration must not be negative")
	}

	sampleRate, err := floatValue(cfg, "sample_rate", 1)
	if err != nil {
		return LatencyConfig{}, err
	}
	if math.IsNaN(sampleRate) || math.IsInf(sampleRate, 0) || sampleRate <= 0 || sampleRate > 1 {
		return LatencyConfig{}, errors.New("sample_rate must be in the range (0, 1]")
	}

	maxEntries, err := uint32Value(cfg, "max_entries", defaultMaxEntries)
	if err != nil {
		return LatencyConfig{}, err
	}
	if maxEntries == 0 || maxEntries > maximumMaxEntries {
		return LatencyConfig{}, fmt.Errorf(
			"max_entries must be in the range [1, %d]", maximumMaxEntries)
	}

	threshold := uint32(sampleRate * float64(math.MaxUint32))
	if threshold == 0 {
		threshold = 1
	}
	return LatencyConfig{
		MinDuration:     minDuration,
		SampleThreshold: threshold,
		MaxEntries:      maxEntries,
	}, nil
}

func configMap(raw any, kind string) (map[string]any, error) {
	if raw == nil {
		return map[string]any{}, nil
	}
	cfg, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s configuration must be a map, got %T", kind, raw)
	}
	return cfg, nil
}

func durationValue(cfg map[string]any, key string, fallback time.Duration) (time.Duration, error) {
	value, ok := cfg[key]
	if !ok {
		return fallback, nil
	}
	switch typed := value.(type) {
	case time.Duration:
		return typed, nil
	case string:
		parsed, err := time.ParseDuration(typed)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", key, typed, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("%s must be a duration string, got %T", key, value)
	}
}

func floatValue(cfg map[string]any, key string, fallback float64) (float64, error) {
	value, ok := cfg[key]
	if !ok {
		return fallback, nil
	}
	switch typed := value.(type) {
	case float64:
		return typed, nil
	case float32:
		return float64(typed), nil
	case int:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case uint64:
		return float64(typed), nil
	default:
		return 0, fmt.Errorf("%s must be numeric, got %T", key, value)
	}
}

func uint32Value(cfg map[string]any, key string, fallback uint32) (uint32, error) {
	value, ok := cfg[key]
	if !ok {
		return fallback, nil
	}
	var converted uint64
	switch typed := value.(type) {
	case uint32:
		return typed, nil
	case uint64:
		converted = typed
	case uint:
		converted = uint64(typed)
	case int:
		if typed < 0 {
			return 0, fmt.Errorf("%s must not be negative", key)
		}
		converted = uint64(typed)
	case int64:
		if typed < 0 {
			return 0, fmt.Errorf("%s must not be negative", key)
		}
		converted = uint64(typed)
	case float64:
		if typed < 0 || math.Trunc(typed) != typed {
			return 0, fmt.Errorf("%s must be a non-negative integer", key)
		}
		converted = uint64(typed)
	default:
		return 0, fmt.Errorf("%s must be an integer, got %T", key, value)
	}
	if converted > math.MaxUint32 {
		return 0, fmt.Errorf("%s exceeds uint32", key)
	}
	return uint32(converted), nil
}
