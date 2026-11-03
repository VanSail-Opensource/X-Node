package agent

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSamplingAndReportingCadenceRemainIndependent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := protocol.Config{Telemetry: protocol.TelemetryPolicy{SampleSeconds: 3, ReportSeconds: 7}}
		cadence := newCadence(config)
		defer cadence.stop()
		start := time.Now()
		for i := range 2 {
			if at := <-cadence.sample.C; at.Sub(start) != time.Duration(i+1)*3*time.Second {
				t.Fatal("sample drift", at.Sub(start))
			}
			cadence.update(config) // Unchanged control frames must not reset either tick.
		}
		if at := <-cadence.report.C; at.Sub(start) != 7*time.Second {
			t.Fatal("report cadence changed with sampling", at.Sub(start))
		}
		config.Telemetry.SampleSeconds, config.Telemetry.ReportSeconds = 2, 5
		cadence.update(config)
		if at := <-cadence.sample.C; at.Sub(start) != 9*time.Second {
			t.Fatal("sample interval change not applied", at.Sub(start))
		}
		if at := <-cadence.report.C; at.Sub(start) != 12*time.Second {
			t.Fatal("report interval change not applied", at.Sub(start))
		}
	})
}
