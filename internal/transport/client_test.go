package transport

import (
	"context"
	"crypto/tls"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWSSAuthenticationAndSerializedConcurrentWrites(t *testing.T) {
	frames := make(chan protocol.Message, 256)
	upgrader := websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" || r.URL.RawQuery != "" {
			t.Error("authentication escaped into URL or header missing")
			http.Error(w, "unauthorized", 401)
			return
		}
		socket, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer socket.Close()
		for {
			var m protocol.Message
			if e = socket.ReadJSON(&m); e != nil {
				return
			}
			frames <- m
			if m.Type == "state.request" {
				_ = socket.WriteJSON(protocol.New("users.sync", "sync", 1, protocol.UsersSync{Users: &[]protocol.User{}}))
			}
		}
	}))
	defer server.Close()
	client := New("wss"+strings.TrimPrefix(server.URL, "https"), "private-token")
	client.Dialer = &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: time.Second}
	client.Hello = func() protocol.Message {
		return protocol.New("agent.hello", "", 0, map[string]string{"agent_id": "fixture"})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case m := <-frames:
		if m.Type != "agent.hello" {
			t.Fatal("hello did not lead connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WSS not connected")
	}
	for i := 0; i < 32; i++ {
		go client.Send(protocol.New("test", "", 0, map[string]int{"i": i}), true)
	}
	select {
	case m := <-client.Incoming:
		if m.Type != "users.sync" {
			t.Fatal("incoming message missing")
		}
	case <-time.After(time.Second):
		t.Fatal("reader not working")
	}
	count := 0
	timeout := time.After(3 * time.Second)
	for count < 32 {
		select {
		case m := <-frames:
			if m.Type == "test" {
				count++
			}
		case <-timeout:
			t.Fatal("concurrent writes were lost")
		}
	}
}
