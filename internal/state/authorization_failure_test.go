package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFailedReplacementOrPersistenceNeverPublishesAuthorization(t *testing.T) {
	store, user := authorizationFixture(t)
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "192.0.2.1", Until: time.Now().UTC().Add(time.Hour)}
	if _, err := store.BlockIPView(protocol.IPBlockKey(user.ID, block.SourceIP), block, &user); err != nil {
		t.Fatal(err)
	}
	before := store.CurrentAuthorization()
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := user
	replacement.ID, replacement.ReplacesID = 9, user.ID
	wrong := replacement
	wrong.UUID = "different-owner"
	for _, users := range [][]protocol.User{{wrong}, {user, replacement}} {
		if view, err := store.AuthorizeView(users, 2); err == nil || view.Sequence != 0 {
			t.Fatal("unverified replacement published admission")
		}
	}
	path := store.path
	store.path = filepath.Join(path, "unwritable", "state.json")
	if view, err := store.AuthorizeView([]protocol.User{replacement}, 2); err == nil || view.Sequence != 0 {
		t.Fatal("failed replacement persistence published admission")
	}
	store.path = path
	after := store.CurrentAuthorization()
	if after.Sequence != before.Sequence || after.Revision != before.Revision || after.Users[0].ID != user.ID || len(after.IPBlocks) != 1 {
		t.Fatal("failed replacement changed the original view")
	}
	if disk, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, disk) {
		t.Fatal("failed replacement changed original durable evidence", err)
	}
	if view, err := store.AuthorizeView([]protocol.User{replacement}, 2); err != nil || view.Sequence != before.Sequence+1 || view.Users[0].ID != 9 {
		t.Fatal("failed publication consumed a revision or sequence", err)
	}
}

func TestFailedIPBlockDoesNotPublishAndViewCopiesRemainIndependent(t *testing.T) {
	store, user := authorizationFixture(t)
	expected, captured, err := store.SubjectView(user.ID)
	if err != nil {
		t.Fatal(err)
	}
	expected.InboundTags[0] = "local-only"
	if captured.Users[0].InboundTags[0] != "in" || store.CurrentAuthorization().Users[0].InboundTags[0] != "in" {
		t.Fatal("subject capture aliases the publication")
	}
	path := store.path
	store.path = filepath.Join(path, "unwritable", "state.json")
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "192.0.2.1", Until: time.Now().UTC().Add(time.Hour)}
	view, err := store.BlockIPView(protocol.IPBlockKey(user.ID, block.SourceIP), block, &user)
	if err == nil || view.Sequence != 0 || len(store.CurrentAuthorization().IPBlocks) != 0 {
		t.Fatal("failed block persistence published a restriction")
	}
	store.path = path
	if store.CurrentAuthorization().Sequence != captured.Sequence {
		t.Fatal("failed block advanced publication order")
	}
}

func TestPublicationSequenceCannotWrapIntoNoChangeSentinel(t *testing.T) {
	store, user := authorizationFixture(t)
	store.authorizationSequence = ^uint64(0)
	if view, err := store.AuthorizeView([]protocol.User{user}, 2); err == nil || view.Sequence != 0 {
		t.Fatal("publication sequence wrapped")
	}
	if store.CurrentAuthorization().Revision != 1 {
		t.Fatal("sequence exhaustion persisted a new revision")
	}
}
