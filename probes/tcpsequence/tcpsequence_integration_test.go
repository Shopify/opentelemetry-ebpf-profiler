//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tcpsequence

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	"go.opentelemetry.io/otel/metric/noop"
)

type sequenceIntervals struct{}

func (sequenceIntervals) MonitorInterval() time.Duration       { return time.Second }
func (sequenceIntervals) TracePollInterval() time.Duration     { return 10 * time.Millisecond }
func (sequenceIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (sequenceIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

type sequenceReportedTrace struct {
	trace *libpf.Trace
	meta  *samples.TraceEventMeta
}

type sequenceCaptureReporter struct {
	traces chan sequenceReportedTrace
}

func (r *sequenceCaptureReporter) ReportTraceEvent(
	trace *libpf.Trace, meta *samples.TraceEventMeta,
) error {
	copied := &libpf.Trace{
		CustomLabels: make(map[libpf.String]libpf.String, len(trace.CustomLabels)),
		Frames:       append(libpf.Frames(nil), trace.Frames...),
	}
	for key, value := range trace.CustomLabels {
		copied.CustomLabels[key] = value
	}
	copiedMeta := *meta
	select {
	case r.traces <- sequenceReportedTrace{trace: copied, meta: &copiedMeta}:
	default:
	}
	return nil
}

var sequenceMetricsOnce sync.Once

func TestTCPSequenceLatencyProfiles(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		buffer := make([]byte, 4096)
		for {
			if _, readErr := io.ReadFull(connection, buffer); readErr != nil {
				return
			}
			if _, writeErr := connection.Write(buffer); writeErr != nil {
				return
			}
		}
	}()

	sequenceMetricsOnce.Do(func() { metrics.Start(noop.Meter{}) })
	reporter := &sequenceCaptureReporter{traces: make(chan sequenceReportedTrace, 512)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter: reporter, Intervals: sequenceIntervals{},
		InterpretersConfig: interpreterconfig.AllInterpreters(),
		SamplesPerSecond:   20, FrameCacheSize: 1024,
		ProbabilisticInterval:  time.Minute,
		ProbabilisticThreshold: tracer.ProbabilisticThresholdMax,
		LoadProbe:              true,
	})
	require.NoError(t, err)
	defer trc.Close()
	trc.StartPIDEventProcessor(ctx)
	traces := make(chan *libpf.EbpfTrace, 4096)
	require.NoError(t, trc.StartMapMonitors(ctx, traces))
	go func() {
		for {
			select {
			case trace, ok := <-traces:
				if !ok {
					return
				}
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	sendProbe, err := NewSendACK(nil)
	require.NoError(t, err)
	require.NoError(t, trc.Enable(sendProbe))
	receiveProbe, err := NewReceive(nil)
	require.NoError(t, err)
	require.NoError(t, trc.Enable(receiveProbe))

	client, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = client.Close()
		<-serverDone
	}()
	payload := make([]byte, 4096)
	response := make([]byte, len(payload))
	found := map[string]bool{}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	for len(found) < 2 {
		_, err = client.Write(payload)
		require.NoError(t, err)
		time.Sleep(2 * time.Millisecond)
		_, err = io.ReadFull(client, response)
		require.NoError(t, err)

		for {
			select {
			case reported := <-reporter.traces:
				sampleType := reported.meta.ProfileType.SampleType
				if sampleType != SendACKSampleType && sampleType != ReceiveSampleType {
					continue
				}
				require.Positive(t, reported.meta.Value)
				require.Equal(t, libpf.Intern("tcp"),
					reported.trace.CustomLabels[libpf.Intern("network.transport")])
				require.Equal(t, libpf.Intern("ok"),
					reported.trace.CustomLabels[libpf.Intern("network.io.status")])
				expectedOperation := "send_to_ack"
				if sampleType == ReceiveSampleType {
					expectedOperation = "receive_consumption"
				}
				require.Equal(t, libpf.Intern(expectedOperation),
					reported.trace.CustomLabels[libpf.Intern("network.operation")])
				require.NotEqual(t, libpf.Intern("0"),
					reported.trace.CustomLabels[libpf.Intern("network.io.bytes")])
				hasUserFrame := false
				for _, frame := range reported.trace.Frames {
					if frame.Value().Type != libpf.KernelFrame {
						hasUserFrame = true
						break
					}
				}
				if hasUserFrame {
					found[sampleType] = true
				}
			default:
				goto drained
			}
		}
	drained:
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for TCP sequence profiles; found %v", found)
		default:
		}
	}
}
