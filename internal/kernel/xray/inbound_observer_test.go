package xray

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	nativeprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type observationInbound struct {
	auth    bool
	failure error
}

func (observationInbound) Network() []xnet.Network { return []xnet.Network{xnet.Network_TCP} }
func (h observationInbound) Process(ctx context.Context, _ xnet.Network, _ stat.Connection, _ routing.Dispatcher) error {
	if h.auth {
		session.InboundFromContext(ctx).User = &nativeprotocol.MemoryUser{Email: "user@1:authenticated"}
	}
	return h.failure
}
func observationSocket(t *testing.T) net.Conn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); done <- conn }()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	conn := <-done
	if conn == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
func TestInboundObservationExcludesRealityAndAuthenticatedTermination(t *testing.T) {
	for _, test := range []struct {
		name          string
		reality, auth bool
		failure       error
		rule          string
	}{
		{"probe", false, false, nil, "xray_tcp_probe"},
		{"invalid", false, false, errors.New("invalid request version"), "xray_invalid"},
		{"auth", false, false, errors.New("invalid request user id"), "xray_auth_failure"},
		{"reality", true, false, errors.New("invalid request user id"), ""},
		{"normal close", false, true, errors.New("connection ended"), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var observations []InboundObservation
			bridge := &integration{Observe: func(event InboundObservation) { observations = append(observations, event) }}
			handler := &observedInbound{Inbound: observationInbound{auth: test.auth, failure: test.failure}, bridge: bridge, tag: "managed", reality: test.reality}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "managed"})
			conn := observationSocket(t)
			_ = handler.Process(ctx, xnet.Network_TCP, &stat.CounterConnection{Connection: conn}, nil)
			if test.rule == "" {
				if len(observations) != 0 {
					t.Fatal("camouflage/authenticated close reported")
				}
				return
			}
			if len(observations) != 1 || observations[0].Rule != test.rule || observations[0].InboundTag != "managed" {
				t.Fatal("wrong classification", observations)
			}
		})
	}
}
func TestRealManagedTCPProbeReachesObserver(t *testing.T) {
	config, port := testConfig(t)
	registry := sessions.New()
	registry.SetUsers(config.Users)
	runtime := New(registry)
	defer runtime.Stop()
	events := make(chan InboundObservation, 4)
	runtime.SetInboundObserver(func(event InboundObservation) { events <- event })
	if err := runtime.Apply(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Rule != "xray_tcp_probe" {
			t.Fatal("TCP probe classification", event)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real native probe was not observed")
	}
}
