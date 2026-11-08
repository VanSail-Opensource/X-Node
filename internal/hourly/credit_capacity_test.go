package hourly

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestUnacknowledgedObligationsAreNeverEvictedAtCapacity(t *testing.T) {
	journal := creditJournal{Version: creditJournalVersion, AgentID: creditFixtureInstall(1).AgentID, HighWater: creditJournalMaxObligations}
	for i := uint64(1); i <= creditJournalMaxObligations; i++ {
		install := creditFixtureInstall(i)
		install.ReservationID = fmt.Sprintf("credit-%d", i)
		journal.Records = append(journal.Records, creditRecord{Install: install, Digest: protocol.HourlyInstallDigest(install)})
	}
	path := privateCreditFixturePath(t)
	writeCreditFixture(t, path, journal)
	store, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	install := creditFixtureInstall(creditJournalMaxObligations + 1)
	if _, err = store.Install(context.Background(), install); !errors.Is(err, ErrCreditCapacity) || store.Healthy() {
		t.Fatal("capacity did not fail hourly closed", err)
	}
	proofs := store.Recovery()
	if len(proofs) != creditJournalMaxObligations {
		t.Fatal("capacity evicted unacknowledged financial evidence", len(proofs))
	}
	for i, proof := range proofs {
		if proof.Install.IssueSequence != uint64(i+1) || proof.UnknownBytes != proof.Install.ByteCeiling || !proof.Recovery {
			t.Fatal("capacity rewrote a retained obligation", proof)
		}
	}
}

func TestHighwaterRejectsReplayAfterAcknowledgmentTombstoneEviction(t *testing.T) {
	journal := creditJournal{Version: creditJournalVersion, AgentID: creditFixtureInstall(1).AgentID, HighWater: creditJournalMaxTombstones + 1}
	for i := uint64(1); i <= creditJournalMaxTombstones+1; i++ {
		install := creditFixtureInstall(i)
		install.ReservationID = fmt.Sprintf("credit-%d", i)
		proof := fixtureCreditProof(install, 100)
		if i <= creditJournalMaxTombstones {
			journal.Tombstones = append(journal.Tombstones, creditTombstone{ReservationID: install.ReservationID, IssueSequence: i, InstallDigest: protocol.HourlyInstallDigest(install), ProofDigest: proof.Digest})
		} else {
			journal.Records = append(journal.Records, creditRecord{Install: install, Digest: protocol.HourlyInstallDigest(install), Proof: &proof})
		}
	}
	path := privateCreditFixturePath(t)
	writeCreditFixture(t, path, journal)
	store, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	proof := store.Recovery()[0]
	ack := protocol.HourlyCreditAck{ReservationID: proof.Install.ReservationID, IssueSequence: proof.Install.IssueSequence, Digest: proof.Digest}
	if err = store.Ack(context.Background(), ack); err != nil || len(store.data.Tombstones) != creditJournalMaxTombstones || store.tombstone("credit-1") >= 0 {
		t.Fatal("ACKed history did not compact within bounds", err)
	}
	restarted, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	old := creditFixtureInstall(1)
	old.ReservationID = "credit-1"
	if _, err = restarted.Install(context.Background(), old); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("evicted digest tombstone allowed stale capacity", err)
	}
	if len(restarted.Recovery()) != 0 {
		t.Fatal("ACKed obligations returned as unsettled")
	}
}
