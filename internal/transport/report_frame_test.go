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

func TestReportFramingNegotiationAndLegacyFallback(t *testing.T) {
	for _, capable := range []bool{true, false} {
		t.Run(fmt.Sprint(capable), func(t *testing.T) {
			result := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers := http.Header{}
				if capable {
					headers.Set(protocol.ReportFramingHeader, protocol.ZstdReportFraming)
				}
				u := websocket.Upgrader{EnableCompression: true, Subprotocols: []string{"x-node.v1"}}
				socket, err := u.Upgrade(w, r, headers)
				if err != nil {
					result <- err
					return
				}
				defer socket.Close()
				socket.SetReadDeadline(time.Now().Add(3 * time.Second))
				decoder, err := protocol.NewReportDecoder()
				if err != nil {
					result <- err
					return
				}
				defer decoder.Close()
				for {
					kind, reader, err := socket.NextReader()
					if err != nil {
						result <- err
						return
					}
					var raw []byte
					if kind == websocket.BinaryMessage {
						raw, err = decoder.Read(reader)
					} else {
						raw, err = protocol.ReadMessagePayload(reader)
					}
					if err != nil {
						result <- err
						return
					}
					message, err := protocol.Parse(raw)
					if err != nil {
						result <- err
						return
					}
					if message.Type != "logs.report" {
						continue
					}
					if (kind == websocket.BinaryMessage) != capable {
						result <- fmt.Errorf("unexpected framing %d", kind)
						return
					}
					if r.Header.Get(protocol.ReportFramingHeader) != protocol.ZstdReportFraming {
						result <- fmt.Errorf("framing not offered")
						return
					}
					result <- nil
					return
				}
			}))
			defer server.Close()
			client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture-token")
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); client.Run(ctx) }()
			defer func() { cancel(); <-done }()
			client.Send(protocol.New("logs.report", "", 0, map[string]any{"entries": []any{}, "dropped": 0}), false)
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("report not delivered")
			}
		})
	}
}
