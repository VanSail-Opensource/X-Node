package hourly

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCompatibilityInspectionLeavesAbsentAndPristineJournalsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "credit.json")
	if required, err := RequiresCompatibleBinary(path); err != nil || required {
		t.Fatal("absent journal blocked first-upgrade rollback", required, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only inspection created a directory", err)
	}
	_, path = openCreditFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if required, err := RequiresCompatibleBinary(path); err != nil || required {
		t.Fatal("pristine journal blocked first-upgrade rollback", required, err)
	}
	assertCreditBytesUnchanged(t, path, before)
}

func TestCompatibilityInspectionPreservesLiveCreditAndRetiredEvidence(t *testing.T) {
	store, path := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if required, err := RequiresCompatibleBinary(path); err != nil || !required {
		t.Fatal("live obligation did not require compatible binary", required, err)
	}
	assertCreditBytesUnchanged(t, path, before)
	if len(store.Recovery()) != 0 || !credit.marker.claim() {
		t.Fatal("inspection recovered or invalidated live admission authority")
	}
	proof, err := store.Seal(context.Background(), SealCandidate{credit: credit, admitted: [2]uint64{100, 200}, unused: 700})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Ack(context.Background(), protocol.HourlyCreditAck{ReservationID: proof.Install.ReservationID, IssueSequence: proof.Install.IssueSequence, Digest: proof.Digest}); err != nil {
		t.Fatal(err)
	}
	if len(store.Recovery()) != 0 || len(store.data.Records) != 0 {
		t.Fatal("fixture still has an outstanding proof")
	}
	if required, err := RequiresCompatibleBinary(path); err != nil || !required {
		t.Fatal("ACK erased downgrade protection for replay evidence", required, err)
	}
	compacted := store.snapshot()
	compacted.RetiredThrough = compacted.HighWater
	compacted.Tombstones = nil
	if err = store.persist(compacted); err != nil {
		t.Fatal(err)
	}
	if required, err := RequiresCompatibleBinary(path); err != nil || !required {
		t.Fatal("compaction erased downgrade protection for high-water fence", required, err)
	}
}

func TestCompatibilityInspectionRejectsCorruptCreditEvidenceWithoutWriting(t *testing.T) {
	store, path := openCreditFixture(t)
	installCreditFixture(t, store)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Retain the old checksum and highest issued sequence.
	raw = bytes.Replace(raw, []byte(`"high_water":"1"`), []byte(`"high_water":"2"`), 1)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = RequiresCompatibleBinary(path); !errors.Is(err, ErrCreditCorrupt) {
		t.Fatal("corrupt journal became downgrade authority", err)
	}
	assertCreditBytesUnchanged(t, path, raw)
}

func assertCreditBytesUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("compatibility inspection changed financial evidence", err)
	}
}
