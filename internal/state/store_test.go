package state

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
	"time"
)

func TestJournalReplayAndAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.AddTraffic(Traffic{1: {10, 20}}); e != nil {
		t.Fatal(e)
	}
	a, e := s.Batch()
	if e != nil {
		t.Fatal(e)
	}
	a.Traffic[1] = [2]uint64{999, 999}
	if e = s.AddTraffic(Traffic{1: {3, 4}}); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	pending, _ := reopened.Batch()
	if pending.ID != a.ID || pending.Traffic[1] != [2]uint64{10, 20} {
		t.Fatal("pending batch was mutated or lost")
	}
	_ = reopened.Ack("wrong")
	still, _ := reopened.Batch()
	if still.ID != pending.ID {
		t.Fatal("wrong ack removed traffic")
	}
	if e = reopened.Ack(pending.ID); e != nil {
		t.Fatal(e)
	}
	next, _ := reopened.Batch()
	if next.ID == pending.ID || next.Traffic[1] != [2]uint64{3, 4} {
		t.Fatal("unsent traffic missing")
	}
}

func TestTemporaryIPBlockAndLimitsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	until := time.Now().UTC().Add(time.Minute)
	block := protocol.IPBlock{SourceIP: "192.0.2.1", UserID: 7, Until: until}
	if e = s.BlockIP("7:192.0.2.1", block); e != nil {
		t.Fatal(e)
	}
	user := protocol.User{ID: 7, UUID: "credential", InboundTags: []string{"in"}, BlockNew: true, SpeedLimitMbps: 100, BurstSpeedLimitMbps: 500, SpeedLimitAfterSeconds: 10}
	if e = s.Authorize([]protocol.User{user}, 1); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	d := reopened.Snapshot()
	if !d.IPBlocks["7:192.0.2.1"].Until.Equal(until) || d.Users[0].SpeedLimitMbps != 100 || d.Users[0].BurstSpeedLimitMbps != 500 {
		t.Fatal("durable restrictions lost")
	}
	if d.Users[0].BlockNew {
		t.Fatal("connection-derived decision restored after restart")
	}
	if e = reopened.BlockIP("7:192.0.2.1", protocol.IPBlock{}); e != nil {
		t.Fatal(e)
	}
	reopened, e = Open(dir)
	if e != nil || len(reopened.Snapshot().IPBlocks) != 0 {
		t.Fatal("unblock not persisted")
	}
}
func TestAuthorizationSurvivesFailedConfiguration(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	u := protocol.User{ID: 1, UUID: "a", InboundTags: []string{"in"}}
	if e := s.Authorize([]protocol.User{u}, 1); e != nil {
		t.Fatal(e)
	}
	c := protocol.Config{Xray: []byte(`{"inbounds":[]}`), Users: []protocol.User{u}}
	if e := s.Accept(c, 1); e != nil {
		t.Fatal(e)
	}
	if e := s.Authorize([]protocol.User{}, 2); e != nil {
		t.Fatal(e)
	}
	s, _ = Open(dir)
	d := s.Snapshot()
	if len(d.Users) != 0 || d.ConfigRevision != 1 || d.Revision != 2 {
		t.Fatal("revocation rolled back")
	}
	if e := s.Authorize([]protocol.User{u}, 1); e == nil {
		t.Fatal("stale authorization accepted")
	}
}
