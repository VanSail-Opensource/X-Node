package agent

import (
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

// Rate/activity baselines belong to sampling, independently of accounting flush
// commands. A barrier cannot consume bytes from the next throughput sample.
func (a *Agent) sampleTraffic() error {
	a.Registry.SampleActivity()
	now := time.Now()
	from := a.lastSample
	if from.IsZero() {
		from = now.Add(-a.desired.SampleInterval())
	}
	current, rates := a.Registry.Counters(), state.Traffic{}
	for id, bytes := range current {
		old := a.previousRates[id]
		up, down := bytes[0], bytes[1]
		if up >= old[0] {
			up -= old[0]
		}
		if down >= old[1] {
			down -= old[1]
		}
		if up != 0 || down != 0 {
			rates[id] = [2]uint64{up, down}
		}
	}
	a.Registry.SetRates(rates, now.Sub(from).Seconds())
	a.previousRates, a.lastSample = current, now
	return a.captureTrafficFrom(current)
}
