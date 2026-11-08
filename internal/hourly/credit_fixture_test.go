package hourly

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func creditFixtureInstall(sequence uint64) protocol.HourlyCreditInstall {
	return protocol.HourlyCreditInstall{
		ReservationID: "credit", IssueSequence: sequence, Owner: protocol.HourlyOwner{ID: "account", Generation: 7},
		DayUTC: "2026-11-09", AgentID: "11111111111111111111111111111111", BootID: "22222222222222222222222222222222",
		SessionID: "33333333333333333333333333333333", ByteCeiling: 1000, Kind: "free",
	}
}

func openCreditFixture(t *testing.T) (*CreditStore, string) {
	t.Helper()
	path := privateCreditFixturePath(t)
	store, err := OpenCreditStore(path)
	if err != nil || !store.Healthy() {
		t.Fatalf("open private credit store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func privateCreditFixturePath(t *testing.T) string {
	t.Helper()
	// testing.TempDir's numbered child follows the process umask. Keep the
	// actual journal parent private without relaxing production permission checks.
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "credit.json")
}

func installCreditFixture(t *testing.T, store *CreditStore) InstalledCredit {
	t.Helper()
	credit, err := store.Install(context.Background(), creditFixtureInstall(1))
	if err != nil {
		t.Fatal(err)
	}
	return credit
}

func writeCreditFixture(t *testing.T, path string, journal creditJournal) {
	t.Helper()
	journal.Digest = creditJournalDigest(journal)
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

func fixtureCreditProof(install protocol.HourlyCreditInstall, used uint64) protocol.HourlyCreditProof {
	proof := protocol.HourlyCreditProof{Install: install, AdmittedUploadBytes: used, UnusedBytes: install.ByteCeiling - used}
	proof.Digest = protocol.HourlyProofDigest(proof)
	return proof
}
