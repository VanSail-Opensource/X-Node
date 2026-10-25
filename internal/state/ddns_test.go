package state

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestDDNSJournalReplayUnchangedGenerationAndRollback(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenDDNS(dir)
	if err != nil {
		t.Fatal(err)
	}
	job := protocol.DDNSJob{ID: "wan", Generation: "generation-1"}
	jobs := []protocol.DDNSJob{job}
	if err = j.Record(job, "203.0.113.7", "2001:db8::7", time.Now(), jobs); err != nil {
		t.Fatal(err)
	}
	first := j.Pending()[0]
	if err = j.Record(job, first.IPv4, first.IPv6, time.Now(), jobs); err != nil || len(j.Pending()) != 1 {
		t.Fatal("unchanged address queued twice", err)
	}
	j, err = OpenDDNS(dir)
	if err != nil || j.Pending()[0] != first {
		t.Fatal("restart lost pending event", err)
	}
	if err = j.Acknowledge([]string{first.ID, first.ID}); err != nil || len(j.Pending()) != 0 {
		t.Fatal("duplicate ack changed delivery", err)
	}
	// An older agent may rewrite its main state file; the DDNS cursor survives.
	if err = AtomicWrite(filepath.Join(dir, "state.json"), []byte(`{"agent_id":"legacy"}`), 0600); err != nil {
		t.Fatal(err)
	}
	j, err = OpenDDNS(dir)
	if err != nil {
		t.Fatal(err)
	}
	job.Generation = "generation-2"
	if err = j.Record(job, first.IPv4, first.IPv6, time.Now(), []protocol.DDNSJob{job}); err != nil {
		t.Fatal(err)
	}
	second := j.Pending()[0]
	if second.ID == first.ID || second.Sequence <= first.Sequence || second.Generation != job.Generation {
		t.Fatal("new binding generation was suppressed", second)
	}
	if err = j.Acknowledge([]string{first.ID}); err != nil || len(j.Pending()) != 1 {
		t.Fatal("old ack removed new event", err)
	}
}

func TestDDNSJournalCapacityAndFailedWritePreserveLastAddress(t *testing.T) {
	j, err := OpenDDNS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job := protocol.DDNSJob{ID: "wan", Generation: "generation"}
	if err = j.Record(job, "203.0.113.7", "", time.Now(), []protocol.DDNSJob{job}); err != nil {
		t.Fatal(err)
	}
	before := j.data.Last[job.ID]
	oldPath := j.path
	j.path = filepath.Join(j.path, "invalid-child")
	if err = j.Record(job, "203.0.113.8", "", time.Now(), []protocol.DDNSJob{job}); err == nil || j.data.Last[job.ID] != before {
		t.Fatal("failed persistence advanced address", err)
	}
	j.path = oldPath
	for len(j.data.Pending) < maxDDNSJournalEntries {
		event := before
		event.ID = fmt.Sprint(len(j.data.Pending))
		j.data.Pending = append(j.data.Pending, event)
	}
	if err = j.Record(job, "203.0.113.9", "", time.Now(), []protocol.DDNSJob{job}); err == nil || j.data.Last[job.ID] != before {
		t.Fatal("full journal advanced address", err)
	}
	if err = os.WriteFile(j.path, []byte(`{"sequence":0,"pending":[{}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenDDNS(filepath.Dir(j.path)); err == nil {
		t.Fatal("malformed durable event accepted")
	}
}
