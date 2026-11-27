package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSharedUsersRetainCurrentAndHistoricalAuthorization(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := protocol.User{ID: 1, UUID: "credential-A", InboundTags: []string{"in"}, AccountingPeriod: "old"}
	new := old
	new.UUID, new.AccountingPeriod, new.BlockNew = "credential-B", "new", true
	config := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`)}
	original := store.path
	if err := store.Authorize([]protocol.User{old}, 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Accept(config, 1); err != nil {
		t.Fatal(err)
	}
	raw, err := ReadRecoveryFile(original, MaxStoreBytes)
	if err != nil || bytes.Count(raw, []byte(old.UUID)) != 1 {
		t.Fatal("accepted users were copied to disk", err)
	}
	// Old readers still see the authoritative top-level credentials on disk.
	var legacy Data
	if err := json.Unmarshal(raw, &legacy); err != nil || len(legacy.Users) != 1 || legacy.Users[0].UUID != old.UUID {
		t.Fatal("older state reader lost current users", err)
	}
	if err := store.Authorize([]protocol.User{new}, 2); err != nil {
		t.Fatal(err)
	}
	if err := store.Stage(config, 2); err != nil {
		t.Fatal(err)
	}
	raw, err = ReadRecoveryFile(original, MaxStoreBytes)
	if err != nil || bytes.Count(raw, []byte(old.UUID)) != 1 || bytes.Count(raw, []byte(new.UUID)) != 1 {
		t.Fatal("staging lost history or duplicated current users", err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := reopened.Snapshot()
	if got.ConfigRevision != 1 || got.Revision != 2 || got.Config.Users[0].AccountingPeriod != "old" ||
		got.DesiredConfig.Users[0].AccountingPeriod != "new" || got.Users[0].BlockNew || got.DesiredConfig.Users[0].BlockNew {
		t.Fatal("recovery changed history, current credentials, or volatile controls")
	}
}

func TestUnchangedStageAndAcceptAvoidDiskWrites(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Authorize([]protocol.User{}, 1); err != nil {
		t.Fatal(err)
	}
	config := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`)}
	if err := store.Stage(config, 1); err != nil {
		t.Fatal(err)
	}
	path := store.path
	store.path = filepath.Join(path, "not-a-directory")
	if err := store.Stage(config, 1); err != nil {
		t.Fatal("retry rewrote the same staged revision", err)
	}
	if err := store.Accept(config, 1); err == nil {
		t.Fatal("undurable activation was accepted")
	}
	store.path = path
	if err := store.Accept(config, 1); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(path, "not-a-directory")
	if err := store.Stage(config, 1); err != nil {
		t.Fatal("restaged an accepted revision", err)
	}
	if err := store.Accept(config, 1); err != nil {
		t.Fatal("rewrote the same accepted revision", err)
	}
}

func BenchmarkPrivateStateEncoding(b *testing.B) {
	users := make([]protocol.User, 4096)
	for i := range users {
		users[i] = protocol.User{ID: i + 1, UUID: fmt.Sprintf("550e8400-e29b-41d4-a716-%012x", i), InboundTags: []string{"paid"}, AccountingPeriod: "billing-period"}
	}
	data := Data{AgentID: "synthetic-node", Users: users, Revision: 1, ConfigRevision: 1, Config: &protocol.Config{
		Xray: json.RawMessage(`{"inbounds":[]}`), Users: users,
	}}
	for _, tc := range []struct {
		name string
		fn   func(Data) ([]byte, error)
	}{
		{"duplicated", func(d Data) ([]byte, error) { return json.Marshal(d) }},
		{"shared", encodeState},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var raw []byte
			var err error
			b.ReportAllocs()
			for b.Loop() {
				if raw, err = tc.fn(data); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(raw)), "state-bytes")
		})
	}
}
