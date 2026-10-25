package transport

import (
	"compress/flate"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

type measuredSocket struct {
	net.Conn
	written atomic.Int64
}

func (c *measuredSocket) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.written.Add(int64(n))
	return n, err
}

func telemetryWireFixture() protocol.TelemetryReport {
	r := protocol.TelemetryReport{AgentID: "agent", BootID: "boot", Time: time.Unix(0, 0).UTC(), Connected: true, Liveness: true, Ready: true, Synchronized: true, Users: protocol.UserMetrics{Connections: map[int]int{}, Status: map[int]protocol.UserLimitStatus{}, Speed: map[int]protocol.UserSpeedStatus{}, Rates: map[int]protocol.UserRate{}}}
	for id := 1; id <= 1000; id++ {
		r.Users.Status[id] = protocol.UserLimitStatus{UserID: id, Scope: "new_connection"}
		r.Users.Speed[id] = protocol.UserSpeedStatus{NormalMbps: 10, BurstMbps: 20, ActiveMbps: 20}
		if id%10 == 0 {
			r.Users.Connections[id] = 2
			r.Users.Rates[id] = protocol.UserRate{UploadBytesPerSecond: 100, DownloadBytesPerSecond: 200, SampleSeconds: 1}
		}
	}
	return r
}

func TestTelemetryWireCompressionAndLegacyFallback(t *testing.T) {
	for _, modern := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "negotiated"}[modern], func(t *testing.T) {
			frames := make(chan protocol.Message, 3)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				header := http.Header{}
				if modern {
					header.Set(protocol.TelemetryFormatHeader, protocol.CompactTelemetryFormat)
				}
				upgrader := websocket.Upgrader{EnableCompression: modern}
				socket, err := upgrader.Upgrade(w, r, header)
				if err != nil {
					return
				}
				defer socket.Close()
				for {
					_, data, err := socket.ReadMessage()
					if err != nil {
						return
					}
					message, err := protocol.Parse(data)
					if err != nil {
						t.Error(err)
						return
					}
					frames <- message
				}
			}))
			defer server.Close()
			nextFrame := func() protocol.Message {
				t.Helper()
				select {
				case message := <-frames:
					return message
				case <-time.After(5 * time.Second):
					t.Fatal("wire frame did not arrive")
					return protocol.Message{}
				}
			}
			var measured *measuredSocket
			dialer := websocket.Dialer{EnableCompression: true, NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				measured = &measuredSocket{Conn: conn}
				return measured, nil
			}}
			socket, response, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), http.Header{protocol.TelemetryFormatHeader: []string{protocol.CompactTelemetryFormat}})
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if err := socket.SetCompressionLevel(flate.BestSpeed); err != nil {
				t.Fatal(err)
			}
			client := New("", "")
			client.compactTelemetry.Store(response.Header.Get(protocol.TelemetryFormatHeader) == protocol.CompactTelemetryFormat)
			baseline := protocol.New("telemetry.report", "", 0, telemetryWireFixture())
			raw, err := json.Marshal(baseline)
			if err != nil {
				t.Fatal(err)
			}
			measured.written.Store(0)
			socket.EnableWriteCompression(false)
			if err := socket.WriteMessage(websocket.TextMessage, raw); err != nil {
				t.Fatal(err)
			}
			legacyBytes := measured.written.Load()
			nextFrame()
			measured.written.Store(0)
			compact := protocol.New("telemetry.compact", "", 0, protocol.CompactTelemetry(telemetryWireFixture()))
			if err := client.writeMessage(socket, compact); err != nil {
				t.Fatal(err)
			}
			wireBytes := measured.written.Load()
			message := nextFrame()
			want := "telemetry.report"
			if modern {
				want = "telemetry.compact"
				if wireBytes*2 > legacyBytes {
					t.Fatalf("wire reduction below 50%%: %d/%d", wireBytes, legacyBytes)
				}
			}
			if message.Type != want {
				t.Fatal("format negotiation/fallback failed", message.Type, want)
			}
			var decoded protocol.TelemetryReport
			if modern {
				var value protocol.CompactTelemetryReport
				if err := protocol.Decode(message.Data, &value); err != nil {
					t.Fatal(err)
				}
				decoded, err = protocol.ExpandTelemetry(value)
			} else {
				err = protocol.Decode(message.Data, &decoded)
			}
			if err != nil || decoded.Users.Connections[10] != 2 || decoded.Users.Rates[10].DownloadBytesPerSecond != 200 {
				t.Fatal("wire metrics changed", err)
			}
			t.Logf("telemetry wire bytes: legacy=%d optimized=%d reduction=%.2f%% negotiated=%t", legacyBytes, wireBytes, 100*(1-float64(wireBytes)/float64(legacyBytes)), modern)
			traffic := protocol.TrafficReport{ID: "agent:1", Traffic: protocol.Traffic{}, Samples: []protocol.TrafficSample{}}
			for id := 1; id <= 100; id++ {
				traffic.Traffic[id] = [2]uint64{9007199254740993, uint64(id)}
			}
			if err := client.writeMessage(socket, protocol.New("traffic.report", traffic.ID, 0, traffic)); err != nil {
				t.Fatal(err)
			}
			message = nextFrame()
			var accounting protocol.TrafficReport
			if err := protocol.Decode(message.Data, &accounting); err != nil || accounting.Traffic[1][0] != 9007199254740993 {
				t.Fatal("report compression changed exact accounting", err)
			}
		})
	}
}
