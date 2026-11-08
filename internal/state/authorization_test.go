package state

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func authorizationFixture(t *testing.T) (*Store, protocol.User) {
	t.Helper()
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	user := protocol.User{ID: 7, UUID: "credential", AccountingPeriod: "paid-period", InboundTags: []string{"in"}}
	if _, err := store.AuthorizeView([]protocol.User{user}, 1); err != nil {
		t.Fatal(err)
	}
	return store, user
}

func TestAuthorizationRemapsScopedBlocksAtomicallyAcrossRestart(t *testing.T) {
	store, user := authorizationFixture(t)
	other := protocol.User{ID: 9, UUID: "retired-credential", AccountingPeriod: "retired-period", InboundTags: []string{"in"}}
	if _, err := store.AuthorizeView([]protocol.User{user, other}, 2); err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 11, 8, 20, 0, 0, 0, time.UTC)
	for _, block := range []protocol.IPBlock{
		{UserID: 7, SourceIP: "192.0.2.1", Until: until},
		{UserID: 9, SourceIP: "192.0.2.1", Until: until.Add(time.Hour)},
		{SourceIP: "192.0.2.1", Until: until.Add(2 * time.Hour)},
	} {
		if err := store.BlockIP(protocol.IPBlockKey(block.UserID, block.SourceIP), block); err != nil {
			t.Fatal(err)
		}
	}
	// A removed subject can retain an older restriction, without occupying the
	// destination identity. The later replacement must merge the longer block.
	if _, err := store.AuthorizeView([]protocol.User{user}, 3); err != nil {
		t.Fatal(err)
	}
	before := store.CurrentAuthorization()
	replacement := user
	replacement.ID, replacement.ReplacesID = 9, user.ID
	view, err := store.AuthorizeView([]protocol.User{replacement}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if view.Sequence <= before.Sequence || view.Revision != 4 || len(view.Users) != 1 || view.Users[0].ID != 9 {
		t.Fatal("authorization and publication were not committed together")
	}
	if _, exists := view.IPBlocks[protocol.IPBlockKey(7, "192.0.2.1")]; exists {
		t.Fatal("source-scoped block survived the actual move")
	}
	if !view.IPBlocks[protocol.IPBlockKey(9, "192.0.2.1")].Until.Equal(until.Add(time.Hour)) ||
		!view.IPBlocks[protocol.IPBlockKey(0, "192.0.2.1")].Until.Equal(until.Add(2*time.Hour)) {
		t.Fatal("replacement weakened a scoped or global block")
	}
	if _, err := store.AuthorizeView([]protocol.User{replacement}, 5); err != nil {
		t.Fatal("idempotent replacement replay failed", err)
	}
	reopened, err := Open(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	current := reopened.CurrentAuthorization()
	if current.Sequence != 1 || current.Revision != 5 || current.Users[0].ID != 9 || len(current.IPBlocks) != 2 ||
		!current.IPBlocks[protocol.IPBlockKey(9, "192.0.2.1")].Until.Equal(until.Add(time.Hour)) {
		t.Fatal("restart lost restrictions or restored a process-local sequence")
	}
}

func TestAuthorizationViewsDoNotAliasInputsOrStore(t *testing.T) {
	store, user := authorizationFixture(t)
	user.Credentials = map[string]json.RawMessage{"in": json.RawMessage(`{"id":"credential"}`)}
	view, err := store.AuthorizeView([]protocol.User{user}, 2)
	if err != nil {
		t.Fatal(err)
	}
	user.Credentials["in"][0] = 'x'
	view.Users[0].Credentials["in"][0] = 'y'
	view.Users[0].InboundTags[0] = "modified"
	current := store.CurrentAuthorization()
	if current.Users[0].Credentials["in"][0] != '{' || current.Users[0].InboundTags[0] != "in" {
		t.Fatal("view or input mutation altered stored authorization")
	}
	block := protocol.IPBlock{SourceIP: "192.0.2.1", Until: time.Now().UTC().Add(time.Hour)}
	view, err = store.BlockIPView(protocol.IPBlockKey(0, block.SourceIP), block, nil)
	if err != nil {
		t.Fatal(err)
	}
	delete(view.IPBlocks, protocol.IPBlockKey(0, block.SourceIP))
	if len(store.CurrentAuthorization().IPBlocks) != 1 {
		t.Fatal("published block map aliases the store")
	}
	raw, err := os.ReadFile(store.path)
	if err != nil || bytes.Contains(raw, []byte("authorizationSequence")) || bytes.Contains(raw, []byte("publication_sequence")) {
		t.Fatal("publication counter entered persisted state", err)
	}
}
