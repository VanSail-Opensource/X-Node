package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradePreservesExistingJournalIdentitiesAndAckDurability(t *testing.T) {
	dir := t.TempDir()
	data := Data{AgentID: ID(), Sequence: 5, Users: nil, Accumulated: Traffic{7: {3, 4}}}
	data.Pending = &Batch{ID: data.AgentID + ":4", Traffic: Traffic{7: {10, 20}}}
	data.Backlog = []*Batch{{ID: data.AgentID + ":5", Traffic: Traffic{7: {1, 2}}}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(Traffic{7: {9, 11}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{data.AgentID + ":4", data.AgentID + ":5", data.AgentID + ":6"} {
		batch, err := s.Batch()
		if err != nil || batch.ID != want || batch.StreamID != "" {
			t.Fatalf("legacy report %d changed: %+v, %v", i, batch, err)
		}
		if i == 0 {
			path := s.path
			s.path = filepath.Join(path, "unwritable", "state.json")
			if advanced, err := s.Acknowledge(batch.ID); err == nil || advanced {
				t.Fatal("historical journal advanced without a durable acknowledgement")
			}
			s.path = path
		}
		if err := s.Ack(want); err != nil {
			t.Fatal(err)
		}
	}
	if batch, err := s.Batch(); err != nil || batch.StreamID != s.StreamID() || batch.Traffic[7] != [2]uint64{9, 11} {
		t.Fatal("new volatile usage did not follow legacy replay", err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pending, err := reopened.Batch(); err != nil || pending != nil {
		t.Fatal("acknowledged history or uncommitted traffic resurrected", err)
	}
}
