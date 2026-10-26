package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/pkg/compute"
)

func (w *computeWorker) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.reset()
			return
		case g := <-w.grants:
			w.execute(ctx, g)
		}
	}
}

func (w *computeWorker) execute(parent context.Context, g protocol.ComputeGrant) {
	accepted := false
	defer func() {
		if !accepted {
			w.send(protocol.New("compute.cancel", g.Offer.Signal.BatchID, 0, g.Offer.Signal), false)
		}
	}()
	ctx, cancel := context.WithDeadline(parent, time.Unix(g.Offer.Deadline, 0))
	w.mu.Lock()
	w.cancel = cancel
	if w.aborted {
		cancel()
	}
	w.mu.Unlock()
	defer func() {
		cancel()
		w.mu.Lock()
		w.cancel = nil
		w.running = false
		w.signal = protocol.ComputeSignal{}
		w.mu.Unlock()
	}()
	for {
		select {
		case <-w.ack:
			continue
		default:
			goto drained
		}
	}
drained:
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if w.eligible != nil && !w.eligible() {
					cancel()
					return
				}
				w.send(protocol.New("compute.heartbeat", g.Offer.Signal.BatchID, 0, g.Offer.Signal), false)
			}
		}
	}()
	defer func() { cancel(); <-done }()
	var b compute.Batch
	if protocol.Decode(g.Input, &b) != nil || compute.Digest(g.Input) != g.Offer.Signal.InputHash || len(b.Tasks) != g.Offer.Items {
		return
	}
	result, err := compute.Run(ctx, b)
	if err != nil {
		return
	}
	compressed, err := compute.Encode(result)
	if err != nil {
		return
	}
	for {
		if err = w.upload(ctx, g.Offer.Signal, compressed); err != nil {
			return
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-w.ack:
			accepted = true
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (w *computeWorker) upload(ctx context.Context, s protocol.ComputeSignal, raw []byte) error {
	hash := compute.Digest(raw)
	total := (len(raw) + compute.ChunkBytes - 1) / compute.ChunkBytes
	for index := 0; index < total; index++ {
		chunk := protocol.ComputeChunk{Signal: s, ResultHash: hash, Index: index, Total: total, Data: base64.StdEncoding.EncodeToString(raw[index*compute.ChunkBytes : min((index+1)*compute.ChunkBytes, len(raw))])}
		message := protocol.New("compute.result", s.BatchID, 0, chunk)
		for !w.send(message, false) {
			timer := time.NewTimer(20 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return errors.New("calculation upload cancelled")
		}
	}
	return nil
}
