package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
)

func TestHourlyTLSReceiptOnlyReplayUsesThisConnectionHeader(t *testing.T) {
	for _, format := range []string{protocol.HourlyAccountingFormat, "", "v2"} {
		t.Run("format="+format, func(t *testing.T) {
			observed := make(chan []protocol.Message, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers := http.Header{}
				if format != "" {
					headers.Set(protocol.HourlyAccountingHeader, format)
				}
				headers.Set(protocol.TrafficStreamHeader, protocol.TrafficStreamFormat)
				socket, err := (&websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}).Upgrade(w, r, headers)
				if err != nil {
					return
				}
				defer socket.Close()
				var reports []protocol.Message
				for {
					var frame protocol.Message
					if err = socket.ReadJSON(&frame); err != nil {
						return
					}
					if frame.Type == "traffic.report" {
						reports = append(reports, frame)
					}
					if frame.Type == "history.barrier" {
						observed <- reports
					}
				}
			}))
			defer server.Close()
			client := New("wss"+strings.TrimPrefix(server.URL, "https"), "fixture")
			client.Dialer = &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			client.hourlyAccounting.Store(true) // Stale compatibility from a prior connection.
			report := protocol.New("traffic.report", "mixed-journal", 0, protocol.TrafficReport{ID: "mixed-journal", StreamID: "11111111111111111111111111111111", Traffic: protocol.Traffic{1: {3, 4}}, DroppedHourlySamples: 1})
			// Ordered traffic is ahead of the disposable barrier in the writer round.
			client.Send(report, true)
			client.Send(protocol.New("history.barrier", "", 0, map[string]any{}), false)
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			done := make(chan bool, 1)
			go func() { done <- client.connect(ctx) }()
			select {
			case reports := <-observed:
				accepted := format == protocol.HourlyAccountingFormat
				if client.Hourly() || client.HourlyAccounting() != accepted || len(reports) != map[bool]int{true: 1, false: 0}[accepted] {
					t.Fatal("TLS receipt header leaked admission or reused stale compatibility")
				}
				if accepted && (reports[0].ID != report.ID || !bytes.Equal(reports[0].Data, report.Data)) {
					t.Fatal("receipt-only socket stripped or rewrote the historical journal")
				}
			case <-ctx.Done():
				t.Fatal("TLS receipt fixture did not drain queued frames")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("TLS receipt connection did not stop")
			}
			if client.HourlyAccounting() || client.Hourly() || client.Connected() {
				t.Fatal("disconnect retained accounting or live admission capability")
			}
		})
	}
}

func TestFailedTLSUpgradeCannotRetainHourlyAccountingCompatibility(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(protocol.HourlyAccountingHeader, protocol.HourlyAccountingFormat)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := New("wss"+strings.TrimPrefix(server.URL, "https"), "fixture")
	client.Dialer = &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client.hourlyAccounting.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if client.connect(ctx) || client.HourlyAccounting() || client.Hourly() || client.Connected() {
		t.Fatal("failed HTTP upgrade retained or installed receipt compatibility")
	}
}
