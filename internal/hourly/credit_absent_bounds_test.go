package hourly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAbsenceCancellationAndPersistenceFailurePreserveEvidence(t *testing.T) {
	store, path := openCreditFixture(t)
	expected := creditFixtureInstall(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.SealAbsent(ctx, expected); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if store.data.HighWater != 0 || len(store.data.Records) != 0 || !store.Healthy() {
		t.Fatal("cancelled absence changed state")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store.write = func(string, []byte) error { return errors.New("constructed absence durability failure") }
	if proof, err := store.SealAbsent(context.Background(), expected); err == nil || proof.Digest != "" {
		t.Fatal("failed write returned a final proof", proof, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || store.data.HighWater != 0 || len(store.Recovery()) != 0 || store.Healthy() {
		t.Fatal("failed absence mutation lost evidence", err)
	}
}

func TestAbsenceCapacityNeverEvictsUnacknowledgedProofs(t *testing.T) {
	journal := creditJournal{Version: creditJournalVersion, AgentID: creditFixtureInstall(1).AgentID, HighWater: creditJournalMaxObligations}
	for sequence := uint64(1); sequence <= creditJournalMaxObligations; sequence++ {
		i := creditFixtureInstall(sequence)
		i.ReservationID = fmt.Sprintf("credit-%d", sequence)
		proof := fixtureCreditProof(i, 0)
		journal.Records = append(journal.Records, creditRecord{Install: i, Digest: protocol.HourlyInstallDigest(i), Proof: &proof})
	}
	path := privateCreditFixturePath(t)
	writeCreditFixture(t, path, journal)
	store, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	i := creditFixtureInstall(creditJournalMaxObligations + 1)
	i.ReservationID = "new-absent-credit"
	if _, err = store.SealAbsent(context.Background(), i); !errors.Is(err, ErrCreditCapacity) {
		t.Fatal(err)
	}
	if len(store.Recovery()) != creditJournalMaxObligations || store.Healthy() {
		t.Fatal("capacity erased retained obligations")
	}
}

func TestOlderJournalMissingRetirementFloorCannotInventAbsence(t *testing.T) {
	i := creditFixtureInstall(2)
	i.ReservationID = "retained-credit"
	proof := fixtureCreditProof(i, 0)
	journal := creditJournal{Version: creditJournalVersion, AgentID: i.AgentID, HighWater: 2, Records: []creditRecord{{Install: i, Digest: protocol.HourlyInstallDigest(i), Proof: &proof}}}
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "retired_through")
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := privateCreditFixturePath(t)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	missing := creditFixtureInstall(1)
	missing.ReservationID = "unproven-old-credit"
	if _, err = store.SealAbsent(context.Background(), missing); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("missing legacy floor fabricated unused bytes", err)
	}
	if store.data.RetiredThrough != 2 {
		t.Fatal("legacy uncertainty floor was not retained")
	}
}
