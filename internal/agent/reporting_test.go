package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	"github.com/gorilla/websocket"
)

func TestReportRequestsCoalesceAndWorkerJoins(t *testing.T) {
	a := &Agent{reportWake: make(chan struct{}, 1)}
	for range 10000 {
		a.requestReports(reportStatus | reportPeriodic)
	}
	if len(a.reportWake) != 1 || a.reportFlags.Load() != reportStatus|reportPeriodic {
		t.Fatal("unbounded report requests")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { a.runReports(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("report worker did not join")
	}
}

func TestTrafficAcknowledgementsDrainSealedBacklogWithoutTimer(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err = store.AddTraffic(state.Traffic{7: {11, 17}}); err != nil {
			t.Fatal(err)
		}
		if _, err = store.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	frames := make(chan protocol.Message, 8)
	upgrader := websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		for {
			var m protocol.Message
			if err = socket.ReadJSON(&m); err != nil {
				return
			}
			if m.Type == "traffic.report" {
				frames <- m
				if err = socket.WriteJSON(protocol.New("traffic.ack", "", 0, map[string]string{"id": m.ID})); err != nil {
					return
				}
			}
		}
	}))
	defer server.Close()
	client := transport.New("ws"+strings.TrimPrefix(server.URL, "http"), "synthetic-token")
	a := &Agent{Store: store, Client: client, reportWake: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	reportsDone := make(chan struct{})
	go func() { a.runReports(ctx); close(reportsDone) }()
	defer func() { cancel(); <-reportsDone }()
	a.requestReports(reportReplay)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	seen := map[string]bool{}
	for len(seen) < 3 {
		select {
		case m := <-frames:
			var batch protocol.TrafficReport
			if err = protocol.Decode(m.Data, &batch); err != nil || batch.Traffic[7] != [2]uint64{11, 17} {
				t.Fatalf("changed accounting: %+v %v", batch, err)
			}
			seen[m.ID] = true
		case m := <-client.Incoming:
			a.handle(ctx, m)
		case <-timer.C:
			t.Fatal("journal waited for reporting timer")
		}
	}
}
