package hourly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestJournalChecksumRejectsOmittedNonHighestRecordWithoutChangingEvidence(t *testing.T) {
	store, path := openCreditFixture(t)
	for sequence := uint64(1); sequence <= 2; sequence++ {
		expected := creditFixtureInstall(sequence)
		if sequence == 2 {
			expected.ReservationID = "highest-credit"
		}
		if _, err := store.SealAbsent(context.Background(), expected); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var journal creditJournal
	if err = json.Unmarshal(raw, &journal); err != nil || journal.Digest != creditJournalDigest(journal) {
		t.Fatal("persist did not checksum the full journal", err)
	}
	journal.Records = journal.Records[1:]
	if validateCreditJournal(journal) != nil {
		t.Fatal("fixture omission should remain structurally valid")
	}
	omitted, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, omitted, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCreditStore(path)
	defer reopened.Close()
	if !errors.Is(err, ErrCreditCorrupt) || reopened.Healthy() {
		t.Fatal("valid-JSON record omission enabled absence proofs", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, omitted) {
		t.Fatal("checksum rejection overwrote original evidence", err)
	}
}

func TestChecksumlessJournalPersistsConservativeFloorBeforeHealthy(t *testing.T) {
	i := creditFixtureInstall(2)
	i.ReservationID = "highest-credit"
	proof := fixtureCreditProof(i, 0)
	journal := creditJournal{Version: creditJournalVersion, AgentID: i.AgentID, HighWater: 2, Records: []creditRecord{{Install: i, Digest: protocol.HourlyInstallDigest(i), Proof: &proof}}}
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	path := privateCreditFixturePath(t)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenCreditStore(path)
	if err != nil || !store.Healthy() {
		t.Fatal("conservative private-format upgrade failed", err)
	}
	defer store.Close()
	raw, err = os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &journal) != nil || journal.RetiredThrough != 2 || !validCreditDigest(journal.Digest) || journal.Digest != creditJournalDigest(journal) {
		t.Fatal("healthy store did not durably checksum the conservative floor", err)
	}
	if _, err = store.SealAbsent(context.Background(), creditFixtureInstall(1)); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("checksum-less omission was guessed unused", err)
	}
	reopened, err := OpenCreditStore(path)
	if err != nil || !reopened.Healthy() || reopened.data.RetiredThrough != 2 {
		t.Fatal("upgraded checksum did not reopen", err)
	}
	defer reopened.Close()
}
