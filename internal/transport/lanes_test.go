package transport

import (
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSaturatedCommandsAndLogsKeepNewestTelemetryAndOrderedTraffic(t *testing.T) {
	c := New("", "")
	for i := range 64 {
		if !c.Send(protocol.New("command.result", fmt.Sprint(i), 0, nil), true) || !c.Send(protocol.New("logs.report", "", 0, i), false) {
			t.Fatal("fixture queue overflow")
		}
	}
	for i := range 200 {
		c.Send(protocol.New("telemetry.report", "", uint64(i), i), false)
	}
	for i := range 8 {
		if !c.Send(protocol.New("traffic.report", fmt.Sprint(i), 0, i), true) {
			t.Fatal("traffic admission failed")
		}
	}
	cursor, traffic, telemetry := 0, 0, false
	for position := 0; ; position++ {
		m, ok := c.next(&cursor)
		if !ok {
			break
		}
		switch m.Type {
		case "telemetry.report":
			if telemetry || m.Revision != 199 || position >= 5 {
				t.Fatal("telemetry stale or starved", position, m.Revision)
			}
			telemetry = true
		case "traffic.report":
			if m.ID != fmt.Sprint(traffic) {
				t.Fatal("durable traffic reordered", m.ID, traffic)
			}
			traffic++
		}
	}
	if !telemetry || traffic != 8 {
		t.Fatal("reports lost under saturation", telemetry, traffic)
	}
}

func TestTrafficOverflowRequestsReplayWithoutReplacingAcceptedBatches(t *testing.T) {
	c := New("", "")
	for i := range 16 {
		if !c.Send(protocol.New("traffic.report", fmt.Sprint(i), 0, i), false) {
			t.Fatal(i)
		}
	}
	if c.Send(protocol.New("traffic.report", "overflow", 0, nil), false) || !c.resync.Load() {
		t.Fatal("durable overflow did not request reconnect/replay")
	}
	for i := range 16 {
		m, ok := c.lanes[1].take()
		if !ok || m.ID != fmt.Sprint(i) {
			t.Fatal("overflow replaced accepted traffic", i, m.ID)
		}
	}
}

func TestMessageLaneBoundsPayloadBytes(t *testing.T) {
	q := newMessageLane(64, 300)
	m := protocol.Message{Data: make([]byte, 100)}
	if ok, _ := q.offer(m, false); !ok {
		t.Fatal("small frame rejected")
	}
	if ok, _ := q.offer(m, false); ok {
		t.Fatal("byte bound exceeded before frame bound")
	}
	q.take()
	if ok, _ := q.offer(m, false); !ok {
		t.Fatal("draining did not release byte budget")
	}
}
