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

func TestDDNSChangeNegotiationAndLegacyReconnectFallback(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "modern"}[accepted], func(t *testing.T) {
			received := make(chan bool, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers := http.Header{}
				if accepted && r.Header.Get(protocol.DDNSChangesHeader) == protocol.DDNSChangesFormat {
					headers.Set(protocol.DDNSChangesHeader, protocol.DDNSChangesFormat)
				}
				socket, err := (&websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}).Upgrade(w, r, headers)
				if err != nil {
					return
				}
				defer socket.Close()
				_ = socket.SetReadDeadline(time.Now().Add(time.Second))
				for {
					_, raw, err := socket.ReadMessage()
					if err != nil {
						received <- false
						return
					}
					frame, err := protocol.Parse(raw)
					if err != nil {
						received <- false
						return
					}
					if frame.Type == "ddns.changes" {
						received <- true
						return
					}
				}
			}))
			defer server.Close()
			client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture")
			client.Hello = func() protocol.Message {
				return protocol.New("agent.hello", "", 0, map[string]string{"agent_id": "node"})
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go client.Run(ctx)
			select {
			case connected := <-client.Status:
				if !connected || client.DDNSChanges() != accepted {
					t.Fatal("bad DDNS negotiation", connected)
				}
			case <-ctx.Done():
				t.Fatal("connection timeout")
			}
			client.Send(protocol.New("ddns.changes", "", 0, protocol.DDNSChanges{}), true)
			select {
			case got := <-received:
				if got != accepted {
					t.Fatal("extension sent to legacy master or lost on modern master", got)
				}
			case <-ctx.Done():
				t.Fatal("frame timeout")
			}
		})
	}
	// A queued event from a previous capable connection must be dropped from the
	// volatile lane without retiring its durable journal event.
	if err := New("", "").writeMessage(nil, protocol.New("ddns.changes", "", 0, protocol.DDNSChanges{})); err != nil {
		t.Fatal(err)
	}
}
