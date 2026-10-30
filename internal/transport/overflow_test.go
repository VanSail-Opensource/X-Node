package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestInboundOverflowDisconnectsOrderedStream(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		for i := 1; i <= 129; i++ {
			if err = socket.WriteJSON(protocol.New("user.controls", "", uint64(i), protocol.UserControls{Users: []protocol.UserControl{}})); err != nil {
				return
			}
		}
		for {
			if _, _, err = socket.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	c := New("ws"+strings.TrimPrefix(server.URL, "http"), "synthetic-token")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- c.connect(ctx) }()
	select {
	case <-done:
		if len(c.Incoming) != 128 || !c.resync.Load() {
			t.Fatal("overflow was silently discarded")
		}
	case <-ctx.Done():
		t.Fatal("overflow did not disconnect")
	}
	for i := 1; i <= 128; i++ {
		if m := <-c.Incoming; m.Revision != uint64(i) {
			t.Fatal("state messages reordered")
		}
	}
}
