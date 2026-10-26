package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/pkg/compute"
)

func TestComputeReservesOneClaimThroughResultAcknowledgement(t *testing.T) {
	sent := make(chan protocol.Message, 32)
	w := newComputeWorker(func(m protocol.Message, _ bool) bool { sent <- m; return true })
	b := compute.Batch{Version: compute.Version, Tasks: []compute.Task{{ID: "quantiles", Kind: "forecast_quantiles_v1", Samples: []float64{1, 2, 3}}}}
	raw, hash, err := compute.DigestBatch(b)
	if err != nil {
		t.Fatal(err)
	}
	offer := protocol.ComputeAnnouncement{Signal: protocol.ComputeSignal{BatchID: "batch", Attempt: 1, InputHash: hash}, Version: compute.Version, Items: 1, Bytes: len(raw), Deadline: time.Now().Add(time.Minute).Unix()}
	var accepted atomic.Int32
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			if w.claim(offer) {
				accepted.Add(1)
			}
		}()
	}
	group.Wait()
	if accepted.Load() != 1 {
		t.Fatal("concurrent claims accepted", accepted.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.run(ctx) }()
	defer func() { cancel(); <-done }()
	w.grant(protocol.ComputeGrant{Offer: offer, Input: raw})
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			t.Fatal("no result")
		case m := <-sent:
			if m.Type != "compute.result" {
				continue
			}
			goto result
		}
	}
result:
	if w.claim(offer) {
		t.Fatal("claimed while result awaited acknowledgement")
	}
	w.signalEvent(offer.Signal, false)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if w.claim(offer) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("acknowledged calculation did not release reservation")
}

func TestDisconnectedComputeReservationCannotAcceptGrant(t *testing.T) {
	w := newComputeWorker(func(protocol.Message, bool) bool { return true })
	offer := protocol.ComputeAnnouncement{Signal: protocol.ComputeSignal{BatchID: "old-session", Attempt: 1, InputHash: compute.Digest(nil)}, Version: compute.Version, Items: 1, Bytes: 1, Deadline: time.Now().Add(time.Minute).Unix()}
	if !w.claim(offer) {
		t.Fatal("initial claim rejected")
	}
	w.reset()
	w.grant(protocol.ComputeGrant{Offer: offer, Input: []byte("{}")})
	select {
	case <-w.grants:
		t.Fatal("disconnected claim accepted a grant")
	default:
	}
}
