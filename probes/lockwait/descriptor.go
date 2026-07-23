// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package lockwait profiles runtime-selected synchronous lock acquisition waits.
package lockwait // import "go.opentelemetry.io/ebpf-profiler/probes/lockwait"

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/usertarget"
)

const (
	maxSuccessfulReturnValues = 4
	maxLabelValueBytes        = 47
	maxSampleTypeBytes        = 128
)

// Labels are descriptor-supplied, low-cardinality profile labels.
type Labels struct {
	Kind      string
	Mode      string
	Operation string
}

// ReturnValueMode controls how the architecture return register is normalized.
type ReturnValueMode uint8

const (
	// ReturnValue64 compares the full 64-bit return register.
	ReturnValue64 ReturnValueMode = iota
	// ReturnValueSigned32 sign-extends the low 32 bits before comparison.
	ReturnValueSigned32
	// ReturnValueUnsigned32 zero-extends the low 32 bits before comparison.
	ReturnValueUnsigned32
)

// ABI describes how the target function reports a successful acquisition.
// An empty SuccessfulReturnValues list accepts every return value, including
// void functions. Otherwise, only an exact normalized value emits a profile.
type ABI struct {
	ReturnValueMode        ReturnValueMode
	SuccessfulReturnValues []int64
}

// Definition describes one generic lock-wait profile and its runtime target.
type Definition struct {
	Target     usertarget.Target
	SampleType string
	Labels     Labels
	ABI        ABI
}

func validateSampleType(value string) error {
	if !utf8.ValidString(value) {
		return errors.New("sample type is not valid UTF-8")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return errors.New("sample type contains a NUL byte")
	}
	if len(value) > maxSampleTypeBytes {
		return fmt.Errorf("sample type exceeds %d bytes", maxSampleTypeBytes)
	}
	return nil
}

func validateLabel(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s contains a NUL byte", name)
	}
	if len(value) > maxLabelValueBytes {
		return fmt.Errorf("%s exceeds %d bytes", name, maxLabelValueBytes)
	}
	return nil
}

func (labels Labels) validate() error {
	return errors.Join(
		validateLabel("lock kind", labels.Kind),
		validateLabel("lock mode", labels.Mode),
		validateLabel("lock operation", labels.Operation),
	)
}

func (labels Labels) profileLabels() map[libpf.String]libpf.String {
	return map[libpf.String]libpf.String{
		libpf.Intern("lock.kind"):      libpf.Intern(labels.Kind),
		libpf.Intern("lock.mode"):      libpf.Intern(labels.Mode),
		libpf.Intern("lock.operation"): libpf.Intern(labels.Operation),
	}
}

func (abi ABI) validated() (ABI, error) {
	if abi.ReturnValueMode > ReturnValueUnsigned32 {
		return ABI{}, fmt.Errorf("unsupported return value mode %d", abi.ReturnValueMode)
	}
	if len(abi.SuccessfulReturnValues) > maxSuccessfulReturnValues {
		return ABI{}, fmt.Errorf("at most %d successful return values are supported",
			maxSuccessfulReturnValues)
	}
	result := ABI{
		ReturnValueMode:        abi.ReturnValueMode,
		SuccessfulReturnValues: slices.Clone(abi.SuccessfulReturnValues),
	}
	seen := make(map[int64]struct{}, len(result.SuccessfulReturnValues))
	for _, value := range result.SuccessfulReturnValues {
		switch result.ReturnValueMode {
		case ReturnValueSigned32:
			if value < -1<<31 || value > 1<<31-1 {
				return ABI{}, fmt.Errorf("successful return value %d does not fit signed 32-bit", value)
			}
		case ReturnValueUnsigned32:
			if value < 0 || value > 1<<32-1 {
				return ABI{}, fmt.Errorf("successful return value %d does not fit unsigned 32-bit", value)
			}
		}
		if _, exists := seen[value]; exists {
			return ABI{}, fmt.Errorf("duplicate successful return value %d", value)
		}
		seen[value] = struct{}{}
	}
	return result, nil
}
