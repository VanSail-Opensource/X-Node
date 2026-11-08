package agent

import (
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Generations are controller-global and never reused, including after pruning
// and re-admission of the same owner/enrollment/period tuple.
func (a *Agent) captureHourly(from time.Time) (captured, deltas []protocol.HourlySample, next map[uint64][2]uint64) {
	if a.hourly == nil || a.hourly.controller == nil {
		return nil, nil, nil
	}
	captured = a.hourly.controller.Samples()
	next = make(map[uint64][2]uint64, len(captured))
	for _, sample := range captured {
		generation := sample.CounterGeneration
		old, seen := a.previousHourly[generation]
		next[generation] = [2]uint64{sample.UploadBytes, sample.DownloadBytes}
		if sample.UploadBytes < old[0] || sample.DownloadBytes < old[1] {
			// A presentation counter regression cannot halt legacy traffic or
			// become fabricated usage. Preserve its baseline and report a loss.
			next[generation] = old
			sample.CounterGeneration = 0
			deltas = append(deltas, sample)
			continue
		}
		up, down := sample.UploadBytes-old[0], sample.DownloadBytes-old[1]
		if up == 0 && down == 0 {
			continue
		}
		if seen && from.After(sample.From) {
			sample.From = from.UTC()
		}
		if sample.From.After(sample.Through) {
			sample.From = sample.Through
		}
		sample.UploadBytes, sample.DownloadBytes = up, down
		deltas = append(deltas, sample)
	}
	return captured, deltas, next
}
