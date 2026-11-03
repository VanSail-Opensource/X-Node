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

func TestActivityNegotiationStripsQueuedExtensionsForLegacyMasters(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		for _, compact := range []bool{false, true} {
			t.Run(fmt.Sprintf("activity=%t/compact=%t", accepted, compact), func(t *testing.T) {
				received := make(chan protocol.Message, 1)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					headers := http.Header{}
					if accepted && r.Header.Get(protocol.ActivityObservationsHeader) == protocol.ActivityObservationsFormat {
						headers.Set(protocol.ActivityObservationsHeader, protocol.ActivityObservationsFormat)
					}
					if compact {
						headers.Set(protocol.TelemetryFormatHeader, protocol.CompactTelemetryFormat)
					}
					socket, err := (&websocket.Upgrader{}).Upgrade(w, r, headers)
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
				at := time.Now().UTC()
				report := protocol.TelemetryReport{Users: protocol.UserMetrics{SampledAt: &at, Connections: map[int]int{7: 2}, ActiveIPObservations: []protocol.IPActivity{{UserID: 7, IP: "8.8.8.8", LastActive: at, Observations: 9007199254740993}}, ObservationDrops: 3}}
				client.activityReports.Store(true)
				client.Send(protocol.New("telemetry.compact", "", 0, protocol.CompactTelemetry(report)), false)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				done := make(chan struct{})
				go func() { client.connect(ctx); close(done) }()
				select {
				case frame := <-received:
					var decoded protocol.TelemetryReport
					var err error
					if compact {
						var c protocol.CompactTelemetryReport
						err = protocol.Decode(frame.Data, &c)
						if err == nil {
							decoded, err = protocol.ExpandTelemetry(c)
						}
					} else {
						err = protocol.Decode(frame.Data, &decoded)
					}
					if err != nil || decoded.Users.Connections[7] != 2 || (decoded.Users.SampledAt != nil) != accepted || (len(decoded.Users.ActiveIPObservations) != 0) != accepted || (decoded.Users.ObservationDrops != 0) != accepted {
						t.Fatal("queued snapshot ignored current negotiation", decoded, err)
					}
				case <-ctx.Done():
					t.Fatal("activity telemetry timed out")
				}
				select {
				case <-done:
					if client.ActivityReports() {
						t.Fatal("activity negotiation survived disconnect")
					}
				case <-ctx.Done():
					t.Fatal("disconnect timed out")
				}
			})
		}
	}
}
