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

func TestTelemetryWireRejectsOversizedCompressedExpansion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{EnableCompression: true}
		socket, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer socket.Close()
		if err := socket.WriteMessage(websocket.TextMessage, []byte(strings.Repeat("x", protocol.MaxFrameBytes+1))); err != nil {
			return
		}
		for {
			if _, _, err := socket.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); client.Run(ctx) }()
	defer func() { cancel(); <-done }()
	for _, want := range []bool{true, false} {
		select {
		case got := <-client.Status:
			if got != want {
				t.Fatal("unexpected connection transition", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("oversized expansion did not close the connection")
		}
	}
	select {
	case <-client.Incoming:
		t.Fatal("oversized input reached JSON processing")
	default:
	}
}
