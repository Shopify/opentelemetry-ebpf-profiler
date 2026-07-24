// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package probeutil

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingCloser struct {
	name   string
	closed *[]string
	err    error
}

func (c *recordingCloser) Close() error {
	*c.closed = append(*c.closed, c.name)
	return c.err
}

func TestResourcesCloseInReverseOrderAndJoinErrors(t *testing.T) {
	var closed []string
	resources := &Resources{}
	resources.Add(
		&recordingCloser{name: "map", closed: &closed},
		&recordingCloser{name: "program", closed: &closed, err: errors.New("program close")},
		&recordingCloser{name: "link", closed: &closed, err: errors.New("link close")},
	)

	err := resources.Close()
	require.Equal(t, []string{"link", "program", "map"}, closed)
	require.ErrorContains(t, err, "link close")
	require.ErrorContains(t, err, "program close")

	require.NoError(t, resources.Close())
	require.Len(t, closed, 3)
}
