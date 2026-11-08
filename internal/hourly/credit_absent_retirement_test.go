package hourly

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAckCompactionPersistsAbsenceUncertaintyFloor(t *testing.T) {
	sequence := uint64(creditJournalMaxTombstones + 1)
	i := creditFixtureInstall(sequence)
	i.ReservationID = fmt.Sprintf("credit-%d", sequence)
	proof := fixtureCreditProof(i, 0)
	journal := creditJournal{Version: creditJournalVersion, AgentID: i.AgentID, HighWater: sequence, Records: []creditRecord{{Install: i, Digest: protocol.HourlyInstallDigest(i), Proof: &proof}}}
	for n := uint64(1); n < sequence; n++ {
		previous := creditFixtureInstall(n)
		previous.ReservationID = fmt.Sprintf("credit-%d", n)
		p := fixtureCreditProof(previous, 0)
		journal.Tombstones = append(journal.Tombstones, creditTombstone{ReservationID: previous.ReservationID, IssueSequence: n, InstallDigest: protocol.HourlyInstallDigest(previous), ProofDigest: p.Digest})
	}
	path := privateCreditFixturePath(t)
	writeCreditFixture(t, path, journal)
	store, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Ack(context.Background(), protocol.HourlyCreditAck{ReservationID: i.ReservationID, IssueSequence: i.IssueSequence, Digest: proof.Digest}); err != nil {
		t.Fatal(err)
	}
	if store.data.RetiredThrough != 1 || len(store.data.Tombstones) != creditJournalMaxTombstones {
		t.Fatal("ACK compaction lost uncertainty floor")
	}
	reopened, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	forgotten := creditFixtureInstall(1)
	forgotten.ReservationID = "credit-1"
	if _, err = reopened.SealAbsent(context.Background(), forgotten); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("evicted ACK was reconstructed as never issued", err)
	}
}

func TestInvalidRetirementFloorFailsClosed(t *testing.T) {
	i := creditFixtureInstall(1)
	proof := fixtureCreditProof(i, 0)
	journal := creditJournal{Version: creditJournalVersion, AgentID: i.AgentID, HighWater: 1, RetiredThrough: 2, Records: []creditRecord{{Install: i, Digest: protocol.HourlyInstallDigest(i), Proof: &proof}}}
	path := privateCreditFixturePath(t)
	writeCreditFixture(t, path, journal)
	store, err := OpenCreditStore(path)
	if !errors.Is(err, ErrCreditCorrupt) || store.Healthy() {
		t.Fatal("impossible retirement floor accepted", err)
	}
}
