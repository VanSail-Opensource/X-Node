package agent

import (
	"slices"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentRejectsHourlyStateWithoutNegotiatedHandshake(t *testing.T) {
	f := newHourlyAgentFixture(t, false, false)
	peer := f.peer(t)
	peer.send(t, protocol.New("state.sync", "unnegotiated-hourly", 1, f.config))
	f.frame(t, peer, "error", "unnegotiated-hourly")
	if f.a.Store.Metadata().Revision != 0 || len(f.a.Store.Snapshot().Users) != 0 {
		t.Fatal("unnegotiated hourly authorization persisted")
	}
	if f.a.Client.Hourly() {
		t.Fatal("missing handshake advertised ready")
	}
}

func TestHourlyJournalFailureKeepsLegacyStateAndRuntimeUsable(t *testing.T) {
	f := newHourlyAgentFixture(t, true, true)
	peer := f.peer(t)
	if peer.session != "" || slices.Contains(f.a.runtimeCapabilities(), protocol.HourlyCapability) {
		t.Fatal("corrupt credit journal advertised hourly support")
	}
	f.config.Users[0].Hourly = nil
	f.apply(t, peer)
	if !f.a.Runtime.Ready() || f.a.Store.Metadata().ConfigRevision != 1 {
		t.Fatal("hourly failure prevented legacy activation")
	}
	hourly := f.config
	hourly.Users = append([]protocol.User(nil), f.config.Users...)
	hourly.Users[0].Hourly = &protocol.HourlyUser{Owner: protocol.HourlyOwner{ID: "account", Generation: 7}, EnrollmentID: "enrollment"}
	peer.send(t, protocol.New("state.sync", "bad-hourly-journal", 2, hourly))
	f.frame(t, peer, "error", "bad-hourly-journal")
	if !f.a.Runtime.Ready() || f.a.Store.Metadata().Revision != 1 || f.a.Store.Metadata().ConfigRevision != 1 {
		t.Fatal("failed hourly admission disturbed legacy state")
	}
}
