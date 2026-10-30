package nlog

import (
	"io"
	"sync/atomic"
	"testing"

	xlog "github.com/xtls/xray-core/common/log"
)

type warningLogger struct{ calls atomic.Int64 }

func (l *warningLogger) Severity() xlog.Severity { return xlog.Severity_Warning }
func (l *warningLogger) Handle(xlog.Message)     { l.calls.Add(1) }

func TestXrayObserverRespectsEnabledStateAndOutputLevel(t *testing.T) {
	stream := NewStream(io.Discard)
	local := &warningLogger{}
	stream.local = local
	var enabled atomic.Bool
	var received atomic.Int64
	stream.SetXrayObserver(enabled.Load, func(string) { received.Add(1) })
	if stream.Severity() != xlog.Severity_Warning {
		t.Fatal("disabled observer changed severity")
	}
	enabled.Store(true)
	if stream.Severity() != xlog.Severity_Info {
		t.Fatal("enabled observer did not receive informational events")
	}
	stream.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: "candidate"})
	if received.Load() != 1 || local.calls.Load() != 0 {
		t.Fatal("observer changed configured output filtering")
	}
	if entries, _ := stream.Drain(); len(entries) != 0 {
		t.Fatal("suppressed information log entered the stream")
	}
	enabled.Store(false)
	stream.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Info, Content: "candidate"})
	if received.Load() != 1 {
		t.Fatal("disabled observer received an event")
	}
}
