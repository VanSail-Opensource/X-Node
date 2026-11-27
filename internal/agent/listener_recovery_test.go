package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	xnet "github.com/xtls/xray-core/common/net"
	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestOccupiedListenerTargetSurvivesRestartAndRecovers(t *testing.T) {
	dir := t.TempDir()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	oldPort := old.Addr().(*net.TCPAddr).Port
	_ = old.Close()
	const kept = "550e8400-e29b-41d4-a716-446655440000"
	const revoked = "550e8400-e29b-41d4-a716-446655440001"
	native := func(port int) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"paid","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}`, port))
	}
	start := func() (*Agent, func()) {
		t.Helper()
		a, err := New(dir, "dev", transport.New("wss://127.0.0.1:1/ws", "fixture"), nlog.NewStream(io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		a.Updater.Client = &http.Client{Transport: offlineHTTP{}}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- a.Run(ctx) }()
		return a, func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}
	}
	a, stop := start()
	stopped := false
	defer func() {
		if !stopped {
			stop()
		}
	}()
	baseline := protocol.Config{Xray: native(oldPort), Users: []protocol.User{
		{ID: 1, UUID: kept, InboundTags: []string{"paid"}},
		{ID: 2, UUID: revoked, InboundTags: []string{"paid"}},
	}}
	a.Client.Incoming <- protocol.New("state.sync", "baseline", 1, baseline)
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 1 })
	blocked := protocol.Clone(baseline)
	blocked.Xray = native(port)
	blocked.Users = blocked.Users[:1]
	a.Client.Incoming <- protocol.New("state.sync", "occupied", 2, blocked)
	await(t, func() bool { return a.Store.Snapshot().DesiredConfig != nil })
	stop()
	stopped = true
	restarted, stopAgain := start()
	defer stopAgain()
	await(t, restarted.Runtime.Ready)
	if d := restarted.Store.Snapshot(); d.Revision != 2 || d.ConfigRevision != 1 || d.DesiredConfig == nil {
		t.Fatal("failed target was accepted or authorization lost", d.Revision, d.ConfigRevision)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reachable")
	}))
	defer origin.Close()
	probe := func(id string) bool {
		t.Helper()
		target := origin.Listener.Addr().(*net.TCPAddr)
		user, err := uuid.ParseString(id)
		if err != nil {
			t.Fatal(err)
		}
		request := &xprotocol.RequestHeader{
			Version: encoding.Version,
			Command: xprotocol.RequestCommandTCP,
			Address: xnet.IPAddress(target.IP),
			Port:    xnet.Port(target.Port),
			User:    &xprotocol.MemoryUser{Account: &vless.MemoryAccount{ID: xprotocol.NewID(user)}},
		}
		var payload bytes.Buffer
		if err := encoding.EncodeRequestHeader(&payload, request, &encoding.Addons{}); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&payload, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", oldPort), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(payload.Bytes()); err != nil {
			return false
		}
		reader := bufio.NewReader(conn)
		if _, err := encoding.DecodeResponseHeader(reader, request); err != nil {
			return false
		}
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && string(body) == "reachable"
	}
	if !probe(kept) || probe(revoked) {
		t.Fatal("cold fallback did not serve still-authorized traffic without reopening revoked access")
	}
	if err = occupied.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(12 * time.Second)
	for !restarted.Runtime.Ready() || restarted.Store.Snapshot().ConfigRevision != 2 {
		if time.Now().After(deadline) {
			t.Fatal("pending listener did not apply after the port was released")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if restarted.Store.Snapshot().DesiredConfig != nil {
		t.Fatal("completed target retained as pending")
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal("recovered listener is not bound", err)
	}
	_ = conn.Close()
}
