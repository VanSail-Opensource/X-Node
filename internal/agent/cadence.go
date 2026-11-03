package agent

import (
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Actor-owned timers keep sampling/reporting independent of maintenance. Reset
// only on a policy change, so unrelated control frames cannot postpone a tick.
type cadence struct {
	sample, report           *time.Ticker
	sampleEvery, reportEvery time.Duration
}

func newCadence(config protocol.Config) *cadence {
	c := &cadence{sample: time.NewTicker(config.SampleInterval()), report: time.NewTicker(config.ReportInterval())}
	c.sampleEvery, c.reportEvery = config.SampleInterval(), config.ReportInterval()
	return c
}

func (c *cadence) update(config protocol.Config) {
	if next := config.SampleInterval(); next != c.sampleEvery {
		c.sample.Reset(next)
		c.sampleEvery = next
	}
	if next := config.ReportInterval(); next != c.reportEvery {
		c.report.Reset(next)
		c.reportEvery = next
	}
}

func (c *cadence) stop() { c.sample.Stop(); c.report.Stop() }
