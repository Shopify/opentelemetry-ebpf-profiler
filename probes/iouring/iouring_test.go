// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package iouring

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const modernSubmitFormat = `name: io_uring_submit_req
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:void * ctx; offset:8; size:8; signed:0;
 field:void * req; offset:16; size:8; signed:0;
 field:unsigned long long user_data; offset:24; size:8; signed:0;
 field:u8 opcode; offset:32; size:1; signed:0;
 field:u32 flags; offset:36; size:4; signed:0;
 field:bool sq_thread; offset:40; size:1; signed:0;
`

const modernCompleteFormat = `name: io_uring_complete
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:void * ctx; offset:8; size:8; signed:0;
 field:void * req; offset:16; size:8; signed:0;
 field:u64 user_data; offset:24; size:8; signed:0;
 field:int res; offset:32; size:4; signed:1;
 field:unsigned cflags; offset:36; size:4; signed:0;
`

const oldSubmitFormat = `name: io_uring_submit_sqe
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:void * ctx; offset:8; size:8; signed:0;
 field:u8 opcode; offset:16; size:1; signed:0;
 field:u64 user_data; offset:24; size:8; signed:0;
 field:bool force_nonblock; offset:32; size:1; signed:0;
 field:bool sq_thread; offset:33; size:1; signed:0;
`

const oldCompleteFormat = `name: io_uring_complete
format:
 field:unsigned short common_type; offset:0; size:2; signed:0;
 field:void * ctx; offset:8; size:8; signed:0;
 field:unsigned long long user_data; offset:16; size:8; signed:0;
 field:long res; offset:24; size:8; signed:1;
`

func TestParseTracepointFormat(t *testing.T) {
	fields, err := parseTracepointFormat(modernSubmitFormat)
	require.NoError(t, err)
	require.Equal(t, tracepointField{offset: 16, size: 8}, fields["req"])
	require.Equal(t, tracepointField{offset: 40, size: 1}, fields["sq_thread"])
}

func TestDiscoverLayoutSupportsRequestPointerCompletion(t *testing.T) {
	root := t.TempDir()
	writeFormat(t, root, "io_uring_submit_req", modernSubmitFormat)
	writeFormat(t, root, "io_uring_complete", modernCompleteFormat)

	layout, err := discoverLayout([]string{root})
	require.NoError(t, err)
	require.Equal(t, "io_uring_submit_req", layout.submit.name)
	require.True(t, layout.submitHasReq)
	require.True(t, layout.completeHasReq)
	require.True(t, layout.completeHasFlags)
	require.Equal(t, uint32(16), layout.complete.fields["req"].offset)
}

func TestDiscoverLayoutSupportsContextUserDataFallback(t *testing.T) {
	root := t.TempDir()
	writeFormat(t, root, "io_uring_submit_sqe", oldSubmitFormat)
	writeFormat(t, root, "io_uring_complete", oldCompleteFormat)

	layout, err := discoverLayout([]string{root})
	require.NoError(t, err)
	require.Equal(t, "io_uring_submit_sqe", layout.submit.name)
	require.False(t, layout.submitHasReq)
	require.False(t, layout.completeHasReq)
	require.False(t, layout.completeHasFlags)
	require.Equal(t, uint32(8), layout.complete.fields["res"].size)
	require.Equal(t, uint32(16), layout.complete.fields["user_data"].offset)
}

func TestDiscoverLayoutRejectsMissingRequiredFields(t *testing.T) {
	root := t.TempDir()
	writeFormat(t, root, "io_uring_submit_req", modernSubmitFormat)
	writeFormat(t, root, "io_uring_complete", "field:void * req; offset:16; size:8; signed:0;")

	_, err := discoverLayout([]string{root})
	require.ErrorContains(t, err, "has no")
}

func TestNewValidatesLatencyConfiguration(t *testing.T) {
	created, err := New(map[string]any{
		"min_duration": "25us",
		"sample_rate":  0.5,
		"max_entries":  123,
	})
	require.NoError(t, err)
	configured := created.(*probe)
	require.Equal(t, uint32(123), configured.maxEntries)
	require.Equal(t, SampleType, configured.ReportMetadata().SampleType)

	_, err = New(map[string]any{"sample_rate": 2})
	require.ErrorContains(t, err, "sample_rate")
}

func writeFormat(t *testing.T, root, event, contents string) {
	t.Helper()
	dir := filepath.Join(root, tracepointGroup, event)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "format"), []byte(contents), 0o644))
}

func Example_parseTracepointFormat() {
	fields, _ := parseTracepointFormat(modernCompleteFormat)
	fmt.Println(fields["res"].offset)
	// Output: 32
}
