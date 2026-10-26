package agent

import (
	"context"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/pkg/compute"
)

// One reservation covers claiming, calculation, upload and acknowledgement.
// No computation or decompression runs on the agent's authoritative state actor.
type computeWorker struct {
	mu               sync.Mutex
	signal           protocol.ComputeSignal
	running, aborted bool
	claimUntil       time.Time
	cancel           context.CancelFunc
	grants           chan protocol.ComputeGrant
	ack              chan struct{}
	send             func(protocol.Message, bool) bool
	eligible         func() bool
}

func newComputeWorker(send func(protocol.Message, bool) bool) *computeWorker {
	return &computeWorker{grants: make(chan protocol.ComputeGrant, 1), ack: make(chan struct{}, 1), send: send}
}

func (w *computeWorker) claim(offer protocol.ComputeAnnouncement) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.running || w.signal.BatchID != "" && time.Now().Before(w.claimUntil) {
		return false
	}
	if offer.Signal.BatchID == "" || len(offer.Signal.BatchID) > 128 || offer.Signal.Attempt < 1 || len(offer.Signal.InputHash) != 64 || offer.Version != compute.Version || offer.Items < 1 || offer.Items > compute.MaxItems || offer.Bytes < 1 || offer.Bytes > compute.MaxInputBytes || offer.Deadline <= time.Now().Unix() || offer.Deadline > time.Now().Add(2*time.Minute).Unix() {
		return false
	}
	w.signal = offer.Signal
	w.aborted = false
	w.claimUntil = time.Now().Add(2 * time.Second)
	return true
}

func (w *computeWorker) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.aborted = true
	if w.cancel != nil {
		w.cancel()
	}
	if !w.running {
		w.signal = protocol.ComputeSignal{}
	}
}

func (w *computeWorker) grant(g protocol.ComputeGrant) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signal != g.Offer.Signal || w.running || w.aborted || time.Now().After(w.claimUntil) || len(g.Input) > compute.MaxInputBytes {
		return
	}
	w.running = true
	select {
	case w.grants <- g:
	default:
		w.running = false
		w.signal = protocol.ComputeSignal{}
	}
}

func (w *computeWorker) signalEvent(s protocol.ComputeSignal, cancel bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.signal != s {
		return
	}
	if cancel {
		w.aborted = true
		if w.cancel != nil {
			w.cancel()
		}
		if !w.running {
			w.signal = protocol.ComputeSignal{}
		}
		return
	}
	if w.running {
		select {
		case w.ack <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) receiveCompute(ctx context.Context, m protocol.Message) {
	if a.compute == nil || !a.Client.ComputePool() {
		return
	}
	switch m.Type {
	case "compute.announce":
		var offer protocol.ComputeAnnouncement
		if protocol.Decode(m.Data, &offer) != nil || !a.computeEligible() || !a.compute.claim(offer) {
			return
		}
		if !a.Client.Send(protocol.New("compute.claim", offer.Signal.BatchID, 0, offer.Signal), false) {
			a.compute.reset()
		}
	case "compute.grant":
		var g protocol.ComputeGrant
		if protocol.Decode(m.Data, &g) == nil {
			a.compute.grant(g)
		}
	case "compute.ack", "compute.cancel":
		var s protocol.ComputeSignal
		if protocol.Decode(m.Data, &s) == nil {
			a.compute.signalEvent(s, m.Type == "compute.cancel")
		}
	}
}

func (a *Agent) computeEligible() bool {
	if a.applying.Load() || !a.Runtime.Ready() {
		return false
	}
	s := a.Sampler.Snapshot()
	if s.Time.IsZero() || time.Since(s.Time) > time.Minute || len(s.CPUUsage) == 0 || s.Memory == nil || s.Memory.UsedPercent >= 85 {
		return false
	}
	mean := 0.0
	for _, v := range s.CPUUsage {
		mean += v
	}
	return mean/float64(len(s.CPUUsage)) < 75
}
