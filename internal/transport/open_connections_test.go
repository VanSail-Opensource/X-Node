package transport

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestOpenConnectionsNegotiationAndQueuedSnapshotFallback(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, compact := range []bool{false, true} {
			t.Run(fmt.Sprintf("open=%t/compact=%t", accepted, compact), func(t *testing.T) {
				received := make(chan protocol.Message, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					headers := http.Header{}
					if accepted && r.Header.Get(protocol.OpenConnectionsHeader) == protocol.OpenConnectionsFormat {
						headers.Set(protocol.OpenConnectionsHeader, protocol.OpenConnectionsFormat)
					}
					if compact {
						headers.Set(protocol.TelemetryFormatHeader, protocol.CompactTelemetryFormat)
					}
					socket, err := (&websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}).Upgrade(w, r, headers)
					if err != nil {
						return
					}
					defer socket.Close()
					_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
					for {
						_, raw, err := socket.ReadMessage()
						if err != nil {
							return
						}
						frame, err := protocol.Parse(raw)
						if err == nil && strings.HasPrefix(frame.Type, "telemetry.") {
							received <- frame
							return
						}
					}
				}))
				defer server.Close()
				client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture")
				report := protocol.TelemetryReport{Users: protocol.UserMetrics{Connections: map[int]int{7: 1}, TotalConnections: map[int]int{7: 2}}}
				// Queue under a previous connection's negotiation before reconnecting.
				client.openConnections.Store(true)
				client.Send(protocol.New("telemetry.compact", "", 0, protocol.CompactTelemetry(report)), false)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				done := make(chan struct{})
				go func() { client.connect(ctx); close(done) }()
				select {
				case frame := <-received:
					var decoded protocol.TelemetryReport
					var err error
					if frame.Type == "telemetry.compact" {
						var rows protocol.CompactTelemetryReport
						err = protocol.Decode(frame.Data, &rows)
						if err == nil {
							decoded, err = protocol.ExpandTelemetry(rows)
						}
					} else {
						err = protocol.Decode(frame.Data, &decoded)
					}
					want := 0
					if accepted {
						want = 2
					}
					if err != nil || decoded.Users.TotalConnections[7] != want || decoded.Users.Connections[7] != 1 {
						t.Fatal("negotiation changed totals or sampled counts", decoded, err)
					}
					if (frame.Type == "telemetry.compact") != compact {
						t.Fatal("telemetry format fallback changed", frame.Type)
					}
				case <-ctx.Done():
					t.Fatal("telemetry timed out")
				}
				select {
				case <-done:
					if client.OpenConnections() {
						t.Fatal("connection negotiation survived disconnect")
					}
				case <-ctx.Done():
					t.Fatal("disconnect timed out")
				}
			})
		}
	}
}
