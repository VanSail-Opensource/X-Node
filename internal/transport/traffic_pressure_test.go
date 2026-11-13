package transport

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestTrafficReplayDuringOutageRetainsOneImmutableCopy(t *testing.T) {
	c := New("", "")
	for i := range 16 {
		for range 128 {
			m := protocol.New("traffic.report", fmt.Sprint(i), 0, map[string]int{"bytes": i})
			if !c.Send(m, true) {
				t.Fatal("duplicate traffic replay exhausted the outbound lane", i)
			}
		}
	}
	if c.Dropped() != 0 || c.resync.Load() || len(c.reset) != 0 {
		t.Fatal("immutable duplicate replay caused a drop or reconnect")
	}
	for i := range 16 {
		m, ok := c.lanes[1].take()
		if !ok || m.ID != fmt.Sprint(i) {
			t.Fatal("coalescing lost/reordered distinct traffic receipts", m.ID)
		}
	}
	if _, ok := c.lanes[1].take(); ok || c.lanes[1].bytes != 0 {
		t.Fatal("duplicate traffic payloads or retained byte budget survived drain")
	}
}

func TestOfflineOverflowResetDoesNotTearDownReplacementConnection(t *testing.T) {
	var connections atomic.Int32
	firstClosed := make(chan struct{})
	frames := make(chan protocol.Message, 128)
	upgrader := websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		if connections.Add(1) == 1 {
			defer close(firstClosed)
		}
		for {
			var message protocol.Message
			if err := socket.ReadJSON(&message); err != nil {
				return
			}
			frames <- message
		}
	}))
	defer server.Close()
	client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture")
	for index := range 64 {
		if !client.Send(protocol.New("command.result", fmt.Sprint(index), 0, nil), true) {
			t.Fatal("fixture filled critical lane too soon")
		}
	}
	if client.Send(protocol.New("command.result", "overflow", 0, nil), true) || len(client.reset) != 1 {
		t.Fatal("fixture did not create an offline reset")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); client.Run(ctx) }()
	defer func() { cancel(); <-done }()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for count := 0; count < 64; {
		select {
		case message := <-frames:
			if message.Type == "command.result" {
				count++
			}
		case <-firstClosed:
			t.Fatal("offline reset tore down the replacement connection")
		case <-timer.C:
			t.Fatal("replacement connection did not drain retained results")
		}
	}
	select {
	case <-firstClosed:
		t.Fatal("stale reset remained after the queue drained")
	case <-time.After(100 * time.Millisecond):
	}
	if connections.Load() != 1 || !client.Connected() {
		t.Fatal("offline overflow caused reconnect churn")
	}
}

func TestConflictingTrafficIdentityCannotReplaceAcceptedBytes(t *testing.T) {
	c := New("", "")
	original := protocol.New("traffic.report", "immutable", 0, map[string]int{"bytes": 12})
	if !c.Send(original, true) {
		t.Fatal("initial report was rejected")
	}
	changed := protocol.New("traffic.report", "immutable", 0, map[string]int{"bytes": 13})
	if c.Send(changed, true) || !c.resync.Load() {
		t.Fatal("one traffic identity accepted different financial content")
	}
	got, ok := c.lanes[1].take()
	if !ok || !bytes.Equal(got.Data, original.Data) {
		t.Fatal("conflicting replay replaced the accepted report")
	}
}
