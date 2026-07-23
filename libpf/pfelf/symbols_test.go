// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestVisitSymbolsReportsMissingSectionSentinel(t *testing.T) {
	file := &File{}
	err := file.VisitSymbols(func(libpf.Symbol) bool { return true })
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrSectionNotPresent))
}
