package transport

import (
	"bytes"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestHourlyQueuedFramesNeverFallBackToLegacyMaster(t *testing.T) {
	client := New("", "")
	for _, name := range []string{"hourly.demand", "hourly.grant.ack", "hourly.credit.proofs"} {
		if err := client.writeMessage(nil, protocol.New(name, "", 0, map[string]any{})); err != nil {
			t.Fatal("legacy peer received queued hourly-only frame", name, err)
		}
	}
	for _, report := range []protocol.TrafficReport{
		{ID: "pending-hourly", Traffic: protocol.Traffic{1: {3, 4}}, HourlySamples: []protocol.HourlySample{{UserID: 1}}},
		{ID: "incomplete-hourly", Traffic: protocol.Traffic{1: {3, 4}}, DroppedHourlySamples: 1},
	} {
		// A nil socket makes any actual write fail. The complete immutable batch
		// must remain unacknowledged, not be rewritten without hourly evidence.
		if err := client.writeMessage(nil, protocol.New("traffic.report", report.ID, 0, report)); err != nil {
			t.Fatal("hourly journal was relabeled for a legacy master", err)
		}
		if len(report.Traffic) != 1 || report.Traffic[1] != [2]uint64{3, 4} {
			t.Fatal("negotiation mutated retained accounting")
		}
	}
}

func TestHourlyDurableProofAndJournalRemainReplayableOnNewCapableSession(t *testing.T) {
	client := New("", "")
	client.hourlyNegotiated.Store(true)
	client.hourlySession.Store("22222222222222222222222222222222")
	old := "11111111111111111111111111111111"
	proof := protocol.HourlyCreditProof{Install: protocol.HourlyCreditInstall{ReservationID: "old-obligation", SessionID: old}}
	for _, frame := range []protocol.Message{
		protocol.New("hourly.credit.proofs", "", 0, protocol.HourlyCreditProofBatch{Proofs: []protocol.HourlyCreditProof{proof}}),
		protocol.New("traffic.report", "immutable-batch", 0, protocol.TrafficReport{ID: "immutable-batch", Traffic: protocol.Traffic{1: {3, 4}}, HourlySamples: []protocol.HourlySample{{UserID: 1}}}),
	} {
		filtered, send, err := client.hourlyMessage(frame)
		if err != nil || !send || !bytes.Equal(filtered.Data, frame.Data) || filtered.ID != frame.ID {
			t.Fatal("capable reconnect rewrote or discarded durable old-session evidence", frame.Type, err)
		}
	}
}

func TestHourlyQueuedSessionFramesCannotCrossReconnect(t *testing.T) {
	client := New("", "")
	client.hourlyNegotiated.Store(true)
	client.hourlySession.Store("22222222222222222222222222222222")
	old := "11111111111111111111111111111111"
	for _, frame := range []protocol.Message{
		protocol.New("hourly.demand", "", 0, protocol.HourlyDemandBatch{SessionID: old, Demands: []protocol.HourlyDemand{}}),
		protocol.New("hourly.grant.ack", "", 0, protocol.HourlyGrantAck{SessionID: old}),
	} {
		if err := client.writeMessage(nil, frame); err != nil {
			t.Fatal("queued live session frame survived reconnect", frame.Type, err)
		}
	}
}
