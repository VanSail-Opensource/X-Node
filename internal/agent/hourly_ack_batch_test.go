package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentBatchesDrainedAcknowledgmentsBeyondSingleFrameCapacity(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	h := f.a.hourly
	drain := h.controller.SetSession(peer.session)
	h.ackMu.Lock()
	for i := range 500 {
		owner := protocol.HourlyOwner{ID: fmt.Sprintf("owner-%d", i)}
		ack := protocol.HourlyGrantAck{SessionID: peer.session, Owner: owner, Nonce: peer.session, Sequence: 1, Applied: true}
		h.acks[owner] = hourlyGrantReceipt{ack: ack, drain: drain}
	}
	h.ackMu.Unlock()
	f.a.flushHourlyGrantAcks(peer.session)
	seen := map[protocol.HourlyOwner]bool{}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for len(seen) < 500 {
		select {
		case event := <-f.frames:
			if event.peer != peer || event.message.Type != "hourly.grant.acks" {
				continue
			}
			var batch protocol.HourlyGrantAckBatch
			if err := protocol.Decode(event.message.Data, &batch); err != nil {
				t.Fatal(err)
			}
			if err := protocol.ValidateHourlyGrantAckBatch(batch); err != nil {
				t.Fatal(err)
			}
			for _, ack := range batch.Acks {
				if seen[ack.Owner] {
					t.Fatal("duplicate acknowledgment")
				}
				seen[ack.Owner] = true
			}
		case <-deadline.C:
			t.Fatal("drained acknowledgments starved behind single-frame lane capacity", len(seen))
		}
	}
}
