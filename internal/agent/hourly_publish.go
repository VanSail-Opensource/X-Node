package agent

import (
	"context"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) publishHourly(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	dirty := true
	var demandAt, proofsAt time.Time
	var session string
	progress := map[string]protocol.HourlyCreditProgress{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.hourly.controller.DemandWake():
			dirty = true
			continue
		case <-ticker.C:
		}
		if !a.checkHourlyHealth() || !a.Client.Hourly() {
			continue
		}
		current, now := a.Client.HourlySession(), time.Now()
		if current != session {
			session, dirty, proofsAt = current, true, time.Time{}
			progress = map[string]protocol.HourlyCreditProgress{}
		}
		a.flushHourlyGrantAcks(session)
		var changed []protocol.HourlyCreditProgress
		for _, item := range a.hourly.controller.CreditProgress(protocol.MaxHourlyItems) {
			if previous, ok := progress[item.ReservationID]; !ok || previous != item {
				changed = append(changed, item)
			}
		}
		var demands []protocol.HourlyDemand
		if now.Sub(demandAt) >= 2*time.Second {
			demands = a.hourly.controller.PendingDemands()
			dirty, demandAt = false, now
		} else if dirty {
			demands = a.hourly.controller.PendingDemand(protocol.MaxHourlyItems)
			dirty = false
		}
		if len(demands)+len(changed) > 0 && a.sendHourlyDemand(session, demands, changed) {
			for _, item := range changed {
				progress[item.ReservationID] = item
			}
		}
		// This cache is only transport optimization, never financial authority.
		if len(progress) > 2048 {
			progress = map[string]protocol.HourlyCreditProgress{}
		}
		if now.Sub(proofsAt) >= 2*time.Second {
			a.publishHourlyProofs()
			proofsAt = now
			progress = map[string]protocol.HourlyCreditProgress{}
		}
	}
}

func (a *Agent) flushHourlyGrantAcks(session string) {
	h := a.hourly
	h.ackMu.Lock()
	defer h.ackMu.Unlock()
	ready := []protocol.HourlyGrantAck{}
	for owner, receipt := range h.acks {
		if receipt.ack.SessionID != session {
			delete(h.acks, owner)
			continue
		}
		select {
		case <-receipt.drain.Done():
			ready = append(ready, receipt.ack)
		default:
		}
	}
	for len(ready) > 0 {
		count := min(len(ready), protocol.MaxHourlyItems)
		batch := protocol.HourlyGrantAckBatch{SessionID: session, Acks: ready[:count]}
		message := protocol.New("hourly.grant.acks", "", 0, batch)
		if len(ready) <= 8 {
			count = 1
			message = protocol.New("hourly.grant.ack", "", 0, ready[0])
		}
		if !a.Client.Send(message, false) {
			break
		}
		for _, ack := range ready[:count] {
			delete(h.acks, ack.Owner)
		}
		ready = ready[count:]
	}
}

func (a *Agent) sendHourlyDemand(session string, demands []protocol.HourlyDemand, progress []protocol.HourlyCreditProgress) bool {
	success := true
	// Separate bounded arrays avoid serializing a growing batch for every item.
	// Frame validation remains explicit even though valid field lengths fit.
	send := func(batch protocol.HourlyDemandBatch) {
		if protocol.ValidateHourlyDemandBatch(batch) != nil || !a.Client.Send(protocol.New("hourly.demand", "", 0, batch), false) {
			success = false
		}
	}
	for len(demands) > 0 {
		count := min(len(demands), protocol.MaxHourlyItems)
		send(protocol.HourlyDemandBatch{SessionID: session, Demands: demands[:count]})
		demands = demands[count:]
	}
	for len(progress) > 0 {
		count := min(len(progress), protocol.MaxHourlyItems)
		send(protocol.HourlyDemandBatch{SessionID: session, Demands: []protocol.HourlyDemand{}, Progress: progress[:count]})
		progress = progress[count:]
	}
	return success
}

func (a *Agent) publishHourlyProofs() {
	batch := protocol.HourlyCreditProofBatch{}
	flush := func() {
		if len(batch.Proofs) > 0 {
			a.Client.Send(protocol.New("hourly.credit.proofs", "", 0, batch), false)
		}
		batch.Proofs = nil
	}
	for _, proof := range a.hourly.store.Recovery() {
		batch.Proofs = append(batch.Proofs, proof)
		if protocol.ValidateHourlyProofBatch(batch) != nil {
			batch.Proofs = batch.Proofs[:len(batch.Proofs)-1]
			flush()
			batch.Proofs = append(batch.Proofs, proof)
		}
	}
	flush()
}
