package agent

import (
	"context"
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type offlineHTTP struct{}

func (offlineHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
}
func TestStateAuthorityGapsAndCachedRecovery(t *testing.T) {
	dir := t.TempDir()
	client := transport.New("wss://127.0.0.1:1/ws", "private-token")
	logs := nlog.NewStream(io.Discard)
	a, e := New(dir, "dev", client, logs)
	if e != nil {
		t.Fatal(e)
	}
	a.Updater.Client = &http.Client{Transport: offlineHTTP{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	c := protocol.Config{Xray: json.RawMessage(`{"log":{"loglevel":"none"},"inbounds":[]}`), Users: []protocol.User{}}
	client.Incoming <- protocol.New("state.sync", "initial", 1, c)
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 1 })
	delta := protocol.New("users.delta", "gap", 3, protocol.UsersDelta{})
	delta.BaseRevision = 0
	client.Incoming <- delta
	time.Sleep(20 * time.Millisecond)
	if a.Store.Snapshot().Revision != 1 {
		t.Fatal("gap mutated state")
	}
	bad := c
	bad.Xray = []byte(`{"inbounds":[{"tag":"broken","protocol":"unsupported"}]}`)
	client.Incoming <- protocol.New("state.sync", "invalid-native", 2, bad)
	await(t, func() bool { return a.Store.Snapshot().Revision == 2 })
	await(t, func() bool { return !a.applying.Load() })
	if a.Store.Snapshot().ConfigRevision != 1 {
		t.Fatal("invalid native config accepted")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	restarted, e := New(dir, "dev", transport.New("wss://127.0.0.1:1/ws", "private-token"), nlog.NewStream(io.Discard))
	if e != nil {
		t.Fatal(e)
	}
	restarted.Updater.Client = &http.Client{Transport: offlineHTTP{}}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { done <- restarted.Run(ctx) }()
	await(t, restarted.Runtime.Ready)
	if len(restarted.Store.Snapshot().Users) != 0 {
		t.Fatal("authorization was reverted on restart")
	}
	cancel()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
func await(t *testing.T, condition func() bool) {
	t.Helper()
	timeout := time.Now().Add(5 * time.Second)
	for time.Now().Before(timeout) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
