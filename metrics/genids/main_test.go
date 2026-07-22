// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaximumMetricIDSupportsReservedGaps(t *testing.T) {
	maximum, err := maximumMetricID([]metricDef{{ID: 0}, {ID: 3}, {ID: 10}})
	require.NoError(t, err)
	require.Equal(t, uint32(10), maximum)
}

func TestMaximumMetricIDRejectsDuplicates(t *testing.T) {
	_, err := maximumMetricID([]metricDef{{ID: 3}, {ID: 3}})
	require.ErrorContains(t, err, "duplicate metric ID 3")
}
