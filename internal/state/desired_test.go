package state

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestPendingDesiredStatePreservesAuthorizationAndExcludesControls(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []protocol.User{{ID: 1, UUID: "private", BlockNew: true}}}
	if err = s.Authorize(c.Users, 1); err != nil {
		t.Fatal(err)
	}
	if err = s.Stage(c, 1); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := reopened.Snapshot()
	if d.DesiredConfig == nil || d.DesiredConfig.Users[0].BlockNew || d.Config != nil || d.ConfigRevision != 0 || d.Users[0].UUID != "private" {
		t.Fatal("pending desired state or volatile control boundary lost")
	}
	if err = reopened.Authorize([]protocol.User{}, 2); err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().DesiredConfig != nil {
		t.Fatal("superseded target survived authorization")
	}
	if err = reopened.Stage(c, 1); err == nil {
		t.Fatal("stale activation target accepted")
	}
}
