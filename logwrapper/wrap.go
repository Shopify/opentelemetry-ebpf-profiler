package logwrapper // import "go.opentelemetry.io/ebpf-profiler/logwrapper"

import (
	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

var (
	SetLogger      = log.SetLogger
	SetDebugLogger = log.SetDebugLogger

	Info   = log.Info
	Infof  = log.Infof
	Debug  = log.Debug
	Debugf = log.Debugf
	Warn   = log.Warn
	Warnf  = log.Warnf
	Error  = log.Error
	Errorf = log.Errorf
	Fatalf = log.Fatalf
)
