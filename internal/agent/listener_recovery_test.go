package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
)

func TestOccupiedListenerTargetSurvivesRestartAndRecovers(t *testing.T) {
	dir := t.TempDir()
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
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
	baseline := protocol.Config{Xray: json.RawMessage(`{"log":{"loglevel":"none"},"inbounds":[]}`), Users: []protocol.User{}}
	a.Client.Incoming <- protocol.New("state.sync", "baseline", 1, baseline)
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 1 })
	blocked := protocol.Clone(baseline)
	blocked.Xray = json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"paid","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}]}`, port))
	a.Client.Incoming <- protocol.New("state.sync", "occupied", 2, blocked)
	await(t, func() bool { return a.Store.Snapshot().DesiredConfig != nil })
	stop()
	restarted, stopAgain := start()
	defer stopAgain()
	await(t, func() bool { return restarted.Store.Snapshot().DesiredConfig != nil })
	if d := restarted.Store.Snapshot(); d.Revision != 2 || d.ConfigRevision != 1 {
		t.Fatal("failed target was accepted or authorization lost", d.Revision, d.ConfigRevision)
	}
	if err = occupied.Close(); err != nil {
		t.Fatal(err)
	}
	await(t, func() bool { return restarted.Runtime.Ready() && restarted.Store.Snapshot().ConfigRevision == 2 })
	if restarted.Store.Snapshot().DesiredConfig != nil {
		t.Fatal("completed target retained as pending")
	}
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal("recovered listener is not bound", err)
	}
	_ = conn.Close()
}
