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

func activationFixture(t *testing.T) (*Agent, protocol.Config) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	a, err := New(t.TempDir(), "fixture", transport.New("wss://127.0.0.1:1/ws", "fixture"), nlog.NewStream(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	a.Updater.Client = &http.Client{Transport: offlineHTTP{}}
	c := protocol.Config{Xray: json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"paid","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}]}`, port)), Users: []protocol.User{{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"paid"}}}}
	return a, c
}

func TestControlsAndAuxiliarySettingsBypassNativeActivation(t *testing.T) {
	a, c := activationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	a.Client.Incoming <- protocol.New("state.sync", "initial", 1, c)
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 1 && !a.applying.Load() })
	before := a.Runtime.Statistics()
	controls := protocol.New("user.controls", "controls", 2, protocol.UserControls{Users: []protocol.UserControl{{ID: 1, BlockNew: true}}})
	controls.BaseRevision = 1
	a.Client.Incoming <- controls
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 2 })
	c.Telemetry.SampleSeconds = 5
	c.Updates.Enabled = false
	c.Torrent.BanSeconds = 120
	a.Client.Incoming <- protocol.New("state.sync", "auxiliary", 3, c)
	await(t, func() bool { return a.Store.Snapshot().ConfigRevision == 3 && !a.applying.Load() })
	after := a.Runtime.Statistics()
	if before.NativeBuilds != after.NativeBuilds || before.InboundBuilds != after.InboundBuilds || before.MatcherBuilds != after.MatcherBuilds || before.Rebuilds != after.Rebuilds {
		t.Fatalf("unrelated native work: before=%+v after=%+v", before, after)
	}
}

func TestControlsDuringPendingBaselineRetainNativeTarget(t *testing.T) {
	a, c := activationFixture(t)
	defer a.Certificates.Stop()
	defer a.Runtime.Stop()
	if err := a.Store.Authorize(c.Users, 1); err != nil {
		t.Fatal(err)
	}
	a.desired, a.hasDesired = c, true
	a.queue(context.Background(), applyJob{Revision: 1, Config: c, RecheckMaterial: true})
	controls := protocol.New("user.controls", "controls", 2, protocol.UserControls{Users: []protocol.UserControl{{ID: 1, BlockNew: true}}})
	controls.BaseRevision = 1
	a.handle(context.Background(), controls)
	if a.Store.Snapshot().ConfigRevision != 0 {
		t.Fatal("unapplied baseline falsely acknowledged")
	}
	job := <-a.apply
	if job.Revision != 2 || !job.RecheckMaterial || !job.Config.Users[0].BlockNew || string(job.Config.Xray) != string(c.Xray) {
		t.Fatal("pending baseline/control overlay lost")
	}
	a.cancelApply()
}
