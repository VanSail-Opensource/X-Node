package state

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestIPMutationRejectsStaleMissingAndInactiveSubjects(t *testing.T) {
	for _, test := range []struct {
		name   string
		update func(protocol.User) []protocol.User
	}{
		{"credential rotation", func(user protocol.User) []protocol.User { user.UUID = "rotated"; return []protocol.User{user} }},
		{"renewed period", func(user protocol.User) []protocol.User {
			user.AccountingPeriod = "successor-period"
			return []protocol.User{user}
		}},
		{"removed", func(protocol.User) []protocol.User { return nil }},
		{"inactive", func(user protocol.User) []protocol.User { user.InboundTags = nil; return []protocol.User{user} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, expected := authorizationFixture(t)
			if _, err := store.AuthorizeView(test.update(expected), 2); err != nil {
				t.Fatal(err)
			}
			before := store.CurrentAuthorization()
			block := protocol.IPBlock{UserID: expected.ID, SourceIP: "192.0.2.1", Until: time.Now().UTC().Add(time.Hour)}
			view, err := store.BlockIPView(protocol.IPBlockKey(expected.ID, block.SourceIP), block, &expected)
			if !errors.Is(err, ErrAuthorizationSubject) || view.Sequence != 0 {
				t.Fatal("stale subject produced a publication")
			}
			if after := store.CurrentAuthorization(); after.Sequence != before.Sequence || len(after.IPBlocks) != 0 {
				t.Fatal("rejected subject altered restrictions")
			}
		})
	}
	store, user := authorizationFixture(t)
	for _, id := range []int{0, -1, user.ID + 1} {
		if _, view, err := store.SubjectView(id); !errors.Is(err, ErrAuthorizationSubject) || view.Sequence != 0 {
			t.Fatal("unknown or non-positive subject was captured")
		}
	}
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "192.0.2.1", Until: time.Now().UTC().Add(time.Hour)}
	if _, err := store.BlockIPView(protocol.IPBlockKey(user.ID, block.SourceIP), block, nil); !errors.Is(err, ErrAuthorizationSubject) {
		t.Fatal("nil expectation authorized a positive scope")
	}
	wrongID := user
	wrongID.ID++
	if _, err := store.BlockIPView(protocol.IPBlockKey(user.ID, block.SourceIP), block, &wrongID); !errors.Is(err, ErrAuthorizationSubject) {
		t.Fatal("credential equality bypassed the explicit subject ID")
	}
}

func TestConditionalIPExpiryDoesNotEraseAnExtendedRestriction(t *testing.T) {
	store, user := authorizationFixture(t)
	cutoff := time.Date(2026, 11, 8, 20, 0, 0, 0, time.UTC)
	key := protocol.IPBlockKey(user.ID, "192.0.2.1")
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "192.0.2.1", Until: cutoff}
	if _, err := store.BlockIPView(key, block, &user); err != nil {
		t.Fatal(err)
	}
	global := protocol.IPBlock{SourceIP: "192.0.2.2", Until: cutoff.Add(-time.Second)}
	if _, err := store.BlockIPView(protocol.IPBlockKey(0, global.SourceIP), global, nil); err != nil {
		t.Fatal(err)
	}
	// An older sweep keeps its cutoff while a later command extends this key.
	block.Until = cutoff.Add(time.Hour)
	extended, err := store.BlockIPView(key, block, &user)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.ExpireIPBlocks(cutoff)
	if err != nil || view.Sequence <= extended.Sequence || len(view.IPBlocks) != 1 || !view.IPBlocks[key].Until.Equal(block.Until) {
		t.Fatal("conditional expiry erased an extension or failed to publish expired globals", err)
	}
	sequence := view.Sequence
	path := store.path
	store.path = filepath.Join(path, "unwritable", "state.json")
	if empty, err := store.ExpireIPBlocks(cutoff); err != nil || empty.Sequence != 0 {
		t.Fatal("unchanged expiry attempted a durable write", err)
	}
	if failed, err := store.ExpireIPBlocks(cutoff.Add(2 * time.Hour)); err == nil || failed.Sequence != 0 {
		t.Fatal("failed expiry published new state")
	}
	if after := store.CurrentAuthorization(); after.Sequence != sequence || len(after.IPBlocks) != 1 {
		t.Fatal("failed expiry changed the publication or persisted view")
	}
	store.path = path
	if final, err := store.ExpireIPBlocks(cutoff.Add(2 * time.Hour)); err != nil || len(final.IPBlocks) != 0 || final.Sequence <= sequence {
		t.Fatal("completed expiry did not publish removal", err)
	}
}

func TestLegacyIPWrapperHandlesIPv6AndScopedZeroUnblock(t *testing.T) {
	store, user := authorizationFixture(t)
	key := protocol.IPBlockKey(user.ID, "2001:db8::1")
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "2001:db8::1", Until: time.Now().UTC().Add(time.Hour)}
	if err := store.BlockIP(key, block); err != nil {
		t.Fatal(err)
	}
	if err := store.BlockIP(key, protocol.IPBlock{}); err != nil {
		t.Fatal("key-only scoped unblock failed", err)
	}
	if len(store.CurrentAuthorization().IPBlocks) != 0 {
		t.Fatal("key-only unblock changed scope")
	}
	unknown := protocol.IPBlock{UserID: user.ID + 1, SourceIP: block.SourceIP, Until: block.Until}
	if err := store.BlockIP(protocol.IPBlockKey(unknown.UserID, unknown.SourceIP), unknown); !errors.Is(err, ErrAuthorizationSubject) {
		t.Fatal("compatibility wrapper admitted an unknown subject")
	}
	if _, err := store.BlockIPView(protocol.IPBlockKey(0, block.SourceIP), block, &user); err == nil {
		t.Fatal("key mismatch changed a global restriction")
	}
}
