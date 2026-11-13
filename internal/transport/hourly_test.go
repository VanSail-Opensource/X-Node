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

func TestHourlyHandshakeRequiresExactEchoAndOperationalCapability(t *testing.T) {
	for _, entry := range []struct {
		name                   string
		enabled                bool
		format                 string
		wrongSession, accepted bool
	}{
		{"accepted", true, protocol.HourlyFormat, false, true},
		{"missing-format", true, "", false, false},
		{"wrong-version", true, "v2", false, false},
		{"wrong-session", true, protocol.HourlyFormat, true, false},
		{"unsupported-agent", false, protocol.HourlyFormat, false, false},
	} {
		t.Run(entry.name, func(t *testing.T) {
			client := New("", "")
			client.SetHourlyEnabled(entry.enabled)
			var callbacks []string
			client.OnHourlySession = func(session string) { callbacks = append(callbacks, session) }
			headers := http.Header{}
			offered := client.offerHourly(headers)
			if entry.enabled && (!protocol.ValidStreamID(offered) || headers.Get(protocol.HourlySessionHeader) != offered || headers.Get(protocol.HourlyHeader) != protocol.HourlyFormat) {
				t.Fatal("agent offered invalid or incomplete hourly session")
			}
			if !entry.enabled && (offered != "" || len(headers) != 0) {
				t.Fatal("unavailable agent advertised hourly enforcement")
			}
			accepted := offered
			if entry.wrongSession || accepted == "" {
				accepted = "ffffffffffffffffffffffffffffffff"
			}
			response := &http.Response{Header: http.Header{}}
			response.Header.Set(protocol.HourlyHeader, entry.format)
			response.Header.Set(protocol.HourlySessionHeader, accepted)
			client.acceptHourly(response, offered)
			client.acceptHourly(response, offered)
			if client.Hourly() != entry.accepted || (client.HourlySession() != "") != entry.accepted {
				t.Fatal("hourly negotiation accepted a partial echo or unsupported capability")
			}
			if entry.accepted {
				if len(callbacks) != 1 || callbacks[0] != offered {
					t.Fatal("session admission fence was missing or repeated")
				}
				client.clearHourlySession()
				if client.Hourly() || client.HourlySession() != "" || len(callbacks) != 2 || callbacks[1] != "" {
					t.Fatal("disconnect retained hourly authority")
				}
				fresh := client.offerHourly(http.Header{})
				if fresh == offered || !protocol.ValidStreamID(fresh) {
					t.Fatal("reconnect reused a stale hourly grant session")
				}
			} else if len(callbacks) != 0 {
				t.Fatal("rejected negotiation installed hourly authority")
			}
		})
	}
}

func TestHourlyDisconnectClearsWireNegotiationAndRetainsBoundedLocalAuthority(t *testing.T) {
	observed := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.Header.Get(protocol.HourlySessionHeader)
		if r.Header.Get(protocol.HourlyHeader) != protocol.HourlyFormat || !protocol.ValidStreamID(session) {
			t.Error("socket handshake omitted hourly offer")
			return
		}
		headers := http.Header{}
		headers.Set(protocol.HourlyHeader, protocol.HourlyFormat)
		headers.Set(protocol.HourlySessionHeader, session)
		socket, err := (&websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}).Upgrade(w, r, headers)
		if err != nil {
			return
		}
		defer socket.Close()
		_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			var frame protocol.Message
			if err = socket.ReadJSON(&frame); err != nil {
				return
			}
			if frame.Type == "hourly.demand" {
				observed <- session
				return
			}
		}
	}))
	defer server.Close()
	client := New("ws"+strings.TrimPrefix(server.URL, "http"), "fixture")
	client.SetHourlyEnabled(true)
	fences := make(chan string, 4)
	client.OnHourlySession = func(session string) { fences <- session }
	client.Hello = func() protocol.Message {
		return protocol.New("agent.hello", "", 0, map[string]any{"capabilities": []string{protocol.HourlyCapability}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- client.connect(ctx) }()
	select {
	case status := <-client.Status:
		if !status || !client.Hourly() {
			t.Fatal("socket did not negotiate hourly enforcement")
		}
	case <-ctx.Done():
		t.Fatal("socket never connected")
	}
	session := client.HourlySession()
	demand := protocol.HourlyDemand{Owner: protocol.HourlyOwner{ID: "owner", Generation: 1}, Nonce: "11111111111111111111111111111111", LifetimeMillis: 10000, PendingBytes: 1, MinAtomicBytes: 1}
	if !client.Send(protocol.New("hourly.demand", "", 0, protocol.HourlyDemandBatch{SessionID: session, Demands: []protocol.HourlyDemand{demand}}), false) {
		t.Fatal("hourly demand not queued")
	}
	select {
	case got := <-observed:
		if got != session {
			t.Fatal("socket session differs from admitted authority")
		}
	case <-ctx.Done():
		t.Fatal("hourly frame missing")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("socket did not disconnect")
	}
	if client.Hourly() || client.HourlySession() != "" || client.Connected() {
		t.Fatal("disconnected socket retained wire negotiation")
	}
	if client.HourlyAuthoritySession() != session {
		t.Fatal("transport loss discarded accepted local grants or credit")
	}
	for _, expected := range []string{session} {
		select {
		case got := <-fences:
			if got != expected {
				t.Fatal("hourly session fence order changed")
			}
		default:
			t.Fatal("missing synchronous session fence")
		}
	}
	select {
	case <-fences:
		t.Fatal("mere transport loss revoked bounded local authority")
	default:
	}
	client.SetHourlyEnabled(false)
	if client.HourlyAuthoritySession() != "" {
		t.Fatal("explicit disable retained local authority")
	}
}

func TestSuccessfulIncompatibleMasterFencesRetainedHourlyAuthority(t *testing.T) {
	client := New("", "")
	client.SetHourlyEnabled(true)
	offered := client.offerHourly(http.Header{})
	response := &http.Response{Header: http.Header{}}
	response.Header.Set(protocol.HourlyHeader, protocol.HourlyFormat)
	response.Header.Set(protocol.HourlySessionHeader, offered)
	client.acceptHourly(response, offered)
	client.suspendHourlySession()
	if client.HourlyAuthoritySession() != offered || client.HourlySession() != "" {
		t.Fatal("suspension confused wire negotiation with retained authority")
	}
	client.acceptHourly(&http.Response{Header: http.Header{}}, client.offerHourly(http.Header{}))
	if client.HourlyAuthoritySession() != "" {
		t.Fatal("a confirmed incompatible master retained old authority")
	}
}

func TestDisablingHourlyCapabilityImmediatelyRevokesSession(t *testing.T) {
	client := New("", "")
	client.SetHourlyEnabled(true)
	offered := client.offerHourly(http.Header{})
	response := &http.Response{Header: http.Header{}}
	response.Header.Set(protocol.HourlyHeader, protocol.HourlyFormat)
	response.Header.Set(protocol.HourlySessionHeader, offered)
	client.acceptHourly(response, offered)
	client.SetHourlyEnabled(false)
	client.acceptHourly(response, offered)
	if client.Hourly() || client.HourlySession() != "" || client.offerHourly(http.Header{}) != "" {
		t.Fatal("disabled enforcement restored cached negotiation")
	}
}
