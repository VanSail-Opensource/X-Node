package state

import (
	"bytes"
	"encoding/json"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"os"
	"testing"
	"time"
)

func TestConnectionAdmissionControlsStayInMemoryAndAreScrubbedOnUpgrade(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour).UTC()
	user := protocol.User{ID: 42, UUID: "11111111-1111-4111-8111-111111111111", BlockNew: true, ValidUntil: &until, AccountingPeriod: "paid-period"}
	if err = store.Authorize([]protocol.User{user}, 1); err != nil {
		t.Fatal(err)
	}
	if err = store.Accept(protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`)}, 1); err != nil {
		t.Fatal(err)
	}
	live := store.Snapshot()
	if !live.Users[0].BlockNew || !live.Config.Users[0].BlockNew {
		t.Fatal("persistence scrub changed live admission decisions")
	}
	raw, err := os.ReadFile(store.path)
	if err != nil || bytes.Contains(raw, []byte(`"block_new"`)) {
		t.Fatal("connection-derived decision persisted")
	}
	restored, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := restored.Snapshot()
	if snapshot.Users[0].BlockNew || snapshot.Config.Users[0].BlockNew || snapshot.Users[0].AccountingPeriod != "paid-period" || !snapshot.Users[0].ValidUntil.Equal(until) {
		t.Fatal("restart altered durable authorization or restored a stale connection block")
	}
	// Simulate an earlier release that wrote its live view directly.
	raw, err = json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(store.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(dir); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(store.path)
	if err != nil || bytes.Contains(raw, []byte(`"block_new"`)) {
		t.Fatal("upgrade retained a historical live decision on disk")
	}
}
