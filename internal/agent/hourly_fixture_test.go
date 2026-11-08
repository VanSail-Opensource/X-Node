package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	"github.com/gorilla/websocket"
)

type hourlyTestPeer struct {
	socket  *websocket.Conn
	session string
	mu      sync.Mutex
}

func (p *hourlyTestPeer) send(t *testing.T, m protocol.Message) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.socket.WriteJSON(m); err != nil {
		t.Fatal(err)
	}
}

type hourlyTestFrame struct {
	peer    *hourlyTestPeer
	message protocol.Message
}
type hourlyAgentFixture struct {
	a      *Agent
	peers  chan *hourlyTestPeer
	frames chan hourlyTestFrame
	audit  chan hourlyTestFrame
	config protocol.Config
}

func newHourlyAgentFixture(t *testing.T, negotiate, corrupt bool) *hourlyAgentFixture {
	return prepareHourlyAgentFixture(t, negotiate, corrupt, nil)
}

func prepareHourlyAgentFixture(t *testing.T, negotiate, corrupt bool, prepare func(string)) *hourlyAgentFixture {
	t.Helper()
	f := &hourlyAgentFixture{peers: make(chan *hourlyTestPeer, 8), frames: make(chan hourlyTestFrame, 1024), audit: make(chan hourlyTestFrame, 1024)}
	stopServer := make(chan struct{})
	upgrader := websocket.Upgrader{Subprotocols: []string{"x-node.v1"}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := http.Header{}
		if r.Header.Get(protocol.TrafficStreamHeader) == protocol.TrafficStreamFormat {
			headers.Set(protocol.TrafficStreamHeader, protocol.TrafficStreamFormat)
		}
		session := r.Header.Get(protocol.HourlySessionHeader)
		if negotiate && session != "" {
			headers.Set(protocol.HourlyHeader, protocol.HourlyFormat)
			headers.Set(protocol.HourlySessionHeader, session)
		}
		socket, err := upgrader.Upgrade(w, r, headers)
		if err != nil {
			return
		}
		defer socket.Close()
		peer := &hourlyTestPeer{socket: socket, session: session}
		select {
		case f.peers <- peer:
		case <-stopServer:
			return
		}
		for {
			var m protocol.Message
			if err = socket.ReadJSON(&m); err != nil {
				return
			}
			select {
			case f.frames <- hourlyTestFrame{peer, m}:
			case <-stopServer:
				return
			}
			select {
			case f.audit <- hourlyTestFrame{peer, m}:
			default:
				t.Error("hourly fixture audit capacity exhausted")
			}
			if m.Type == "traffic.report" {
				peer.mu.Lock()
				err = socket.WriteJSON(protocol.New("traffic.ack", "", 0, map[string]string{"id": m.ID}))
				peer.mu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}))
	t.Cleanup(func() { close(stopServer); server.Close() })
	dir := t.TempDir()
	if prepare != nil {
		prepare(dir)
	}
	if corrupt {
		if err := os.WriteFile(filepath.Join(dir, "hourly-credits.json"), []byte("["), 0600); err != nil {
			t.Fatal(err)
		}
	}
	client := transport.New("wss"+strings.TrimPrefix(server.URL, "https"), "fixture-hourly-token")
	client.Dialer = &websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: time.Second}
	a, err := New(dir, "fixture", client, nlog.NewStream(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	a.Updater.Client = &http.Client{Transport: offlineHTTP{}}
	f.a = a
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	until := time.Now().UTC().Add(time.Hour)
	f.config = protocol.Config{Xray: json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"paid","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}]}`, port)), Users: []protocol.User{{ID: 1, UUID: "550e8400-e29b-41d4-a716-446655440000", InboundTags: []string{"paid"}, AccountingPeriod: "hourly-period", ValidUntil: &until, Hourly: &protocol.HourlyUser{Owner: protocol.HourlyOwner{ID: "account", Generation: 7}, EnrollmentID: "enrollment"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("hourly fixture agent did not stop")
		}
	})
	return f
}

func (f *hourlyAgentFixture) peer(t *testing.T) *hourlyTestPeer {
	t.Helper()
	select {
	case p := <-f.peers:
		return p
	case <-time.After(8 * time.Second):
		t.Fatal("hourly agent did not connect")
		return nil
	}
}
func (f *hourlyAgentFixture) frame(t *testing.T, p *hourlyTestPeer, kind, id string) protocol.Message {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-f.frames:
			if event.peer == p && event.message.Type == kind && (id == "" || event.message.ID == id) {
				return event.message
			}
		case <-timer.C:
			t.Fatalf("missing hourly frame %s/%s", kind, id)
			return protocol.Message{}
		}
	}
}
func (f *hourlyAgentFixture) command(t *testing.T, p *hourlyTestPeer, id, name string, args any) JobResult {
	t.Helper()
	await(t, func() bool { f.a.Jobs.mu.Lock(); defer f.a.Jobs.mu.Unlock(); return len(f.a.Jobs.running) < 2 })
	p.send(t, protocol.New("command", id, 0, map[string]any{"name": name, "args": args}))
	var result JobResult
	if err := protocol.Decode(f.frame(t, p, "command.result", id).Data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func (f *hourlyAgentFixture) apply(t *testing.T, p *hourlyTestPeer) {
	t.Helper()
	p.send(t, protocol.New("state.sync", "hourly-state", 1, f.config))
	f.frame(t, p, "state.applied", "hourly-state")
}
func (f *hourlyAgentFixture) install(p *hourlyTestPeer, id string, sequence uint64) protocol.HourlyCreditInstall {
	return protocol.HourlyCreditInstall{ReservationID: id, IssueSequence: sequence, Owner: f.config.Users[0].Hourly.Owner, DayUTC: time.Now().UTC().Format(time.DateOnly), AgentID: f.a.Store.Metadata().AgentID, BootID: f.a.BootID, SessionID: p.session, ByteCeiling: 1000, Kind: "free"}
}
