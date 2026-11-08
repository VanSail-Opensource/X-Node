package sessions

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestAuthorizationSequenceRejectsStaleBlockUnblockExpiryAndUsers(t *testing.T) {
	registry := New()
	user := identityIPUser(1, testUser().UUID)
	view := func(sequence, revision uint64, users []protocol.User, blocks map[string]protocol.IPBlock) state.AuthorizationView {
		return state.AuthorizationView{Sequence: sequence, Revision: revision, Users: users, IPBlocks: blocks}
	}
	users := []protocol.User{user}
	block := protocol.IPBlock{UserID: user.ID, SourceIP: "192.0.2.1", Until: time.Now().Add(time.Hour)}
	blocked := map[string]protocol.IPBlock{IPBlockKey(user.ID, block.SourceIP): block}
	initial := view(1, 1, users, nil)
	if !registry.ApplyAuthorization(initial) || !registry.ApplyAuthorization(view(2, 1, users, blocked)) {
		t.Fatal("committed initial/block views were rejected")
	}
	if registry.ApplyAuthorization(initial) {
		t.Fatal("delayed unblock view replaced a newer block")
	}
	assertIPDenied(t, registry, user.ID, protocol.UserEmail(user, "in"), block.SourceIP, "tcp")
	for _, sequence := range []uint64{3, 5} {
		if sequence == 5 && !registry.ApplyAuthorization(view(4, 1, users, blocked)) {
			t.Fatal("fresh reblock was rejected")
		}
		if !registry.ApplyAuthorization(view(sequence, 1, users, nil)) {
			t.Fatal("fresh unblock/expiry view was rejected")
		}
		if registry.ApplyAuthorization(view(sequence-1, 1, users, blocked)) {
			t.Fatal("delayed block resurrected an expired/unblocked restriction")
		}
		lease, err := acquire(registry, user, block.SourceIP, "udp")
		if err != nil {
			t.Fatal("stale block remained authoritative", err)
		}
		lease.Close()
	}
	renewed := user
	renewed.UUID, renewed.AccountingPeriod = "550e8400-e29b-41d4-a716-446655440099", "purchase-two"
	if !registry.ApplyAuthorization(view(6, 2, []protocol.User{renewed}, nil)) {
		t.Fatal("fresh credential/period view rejected")
	}
	if registry.ApplyAuthorization(view(5, 1, users, blocked)) || registry.ApplyAuthorization(view(6, 3, users, blocked)) || registry.ApplyAuthorization(view(7, 1, users, blocked)) {
		t.Fatal("stale/equal sequence or older revision replaced current users")
	}
	if old, err := acquire(registry, user, block.SourceIP, "tcp"); err == nil {
		old.Close()
		t.Fatal("old credentials became valid again")
	}
	fresh, err := acquire(registry, renewed, block.SourceIP, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
}

func TestNewerIPViewCanPublishReplacementBeforeAuthorizationActor(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	before := identityIPUser(1, testUser().UUID)
	initial, err := store.AuthorizeView([]protocol.User{before}, 1)
	if err != nil {
		t.Fatal(err)
	}
	registry := New()
	registry.ApplyAuthorization(initial)
	lease, err := acquire(registry, before, "198.51.100.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	after := before
	after.ID, after.ReplacesID = 100, before.ID
	authorization, err := store.AuthorizeView([]protocol.User{after}, 2)
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.IPBlock{UserID: after.ID, SourceIP: "192.0.2.1", Until: time.Now().Add(time.Hour)}
	newer, err := store.BlockIPView(IPBlockKey(after.ID, block.SourceIP), block, &after)
	if err != nil {
		t.Fatal(err)
	}
	if !registry.ApplyAuthorization(newer) || registry.ApplyAuthorization(authorization) {
		t.Fatal("IP publication did not fence the delayed authorization view")
	}
	if lease.closed || lease.Info.UserID != after.ID || registry.Summary().TotalConnections[after.ID] != 1 {
		t.Fatal("early IP publication lost the verified replacement or its reservation")
	}
	assertIPDenied(t, registry, after.ID, protocol.UserEmail(after, "in"), block.SourceIP, "tcp")
	assertIPDenied(t, registry, before.ID, protocol.UserEmail(before, "in"), block.SourceIP, "udp")
}

func TestInvalidReplacementLeavesEntireRegistryAuthorizationUnchanged(t *testing.T) {
	for _, change := range []func(*protocol.User){
		func(user *protocol.User) { user.UUID = "550e8400-e29b-41d4-a716-446655440099" },
		func(user *protocol.User) { user.AccountingPeriod = "different-purchase" },
		func(user *protocol.User) { user.ID = 2 },
	} {
		registry := New()
		before := identityIPUser(1, testUser().UUID)
		other := identityIPUser(2, "550e8400-e29b-41d4-a716-446655440002")
		block := protocol.IPBlock{UserID: before.ID, SourceIP: "192.0.2.9", Until: time.Now().Add(time.Hour)}
		if !registry.ApplyAuthorization(state.AuthorizationView{Sequence: 1, Revision: 1, Users: []protocol.User{before, other}, IPBlocks: map[string]protocol.IPBlock{IPBlockKey(before.ID, block.SourceIP): block}}) {
			t.Fatal("initial authorization rejected")
		}
		after := before
		after.ID, after.ReplacesID = 100, before.ID
		change(&after)
		registry.SetUsers([]protocol.User{after})
		if registry.ApplyAuthorization(state.AuthorizationView{Sequence: 2, Revision: 2, Users: []protocol.User{after}}) {
			t.Fatal("invalid replacement view was admitted")
		}
		assertIPDenied(t, registry, before.ID, protocol.UserEmail(before, "in"), block.SourceIP, "udp")
		for _, current := range []protocol.User{before, other} {
			lease, err := acquire(registry, current, "192.0.2.1", "tcp")
			if err != nil {
				t.Fatal("invalid replacement partially changed authorization", err)
			}
			lease.Close()
		}
	}
}

func TestDropIPSubjectCannotFollowAliasesOrStaleCredentials(t *testing.T) {
	registry := New()
	before := identityIPUser(1, testUser().UUID)
	other := identityIPUser(2, "550e8400-e29b-41d4-a716-446655440002")
	registry.SetUsers([]protocol.User{before, other})
	first, err := acquire(registry, before, "192.0.2.1", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquire(registry, other, "192.0.2.1", "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	after := before
	after.ID, after.ReplacesID = 100, before.ID
	registry.SetUsers([]protocol.User{after, other})
	wrongCredential, wrongPeriod := after, after
	wrongCredential.UUID, wrongPeriod.AccountingPeriod = "550e8400-e29b-41d4-a716-446655440099", "another-purchase"
	for _, stale := range []protocol.User{before, wrongCredential, wrongPeriod} {
		if count, err := registry.DropIPSubject("192.0.2.1", &stale); err == nil || count != 0 || first.closed || second.closed {
			t.Fatal("stale subject closed a live lease")
		}
	}
	if count, err := registry.DropIPSubject("192.0.2.1", &after); err != nil || count != 1 || !first.closed || second.closed {
		t.Fatal("current subject dropped another user's lease")
	}
	if count, err := registry.DropIPSubject("192.0.2.1", nil); err != nil || count != 1 || !second.closed {
		t.Fatal("global drop did not close the remaining owner")
	}
}
