package hourly

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFinalProofSurvivesRestartWithoutBecomingUnknown(t *testing.T) {
	store, path := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	if !credit.marker.claim() {
		t.Fatal("activation unavailable")
	}
	proof, err := store.Seal(context.Background(), SealCandidate{credit: credit, admitted: [2]uint64{200, 300}, unused: 500})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if recovered := restarted.Recovery(); len(recovered) != 1 || recovered[0] != proof || recovered[0].Recovery {
		t.Fatal("durable admitted/unused evidence changed after restart", recovered)
	}
}

func TestFailedAckCannotLoseProofOrRestoreSpendableCredit(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "after-rename-barrier"}[afterWrite], func(t *testing.T) {
			store, path := openCreditFixture(t)
			credit := installCreditFixture(t, store)
			proof, err := store.SealUnclaimed(context.Background(), credit)
			if err != nil {
				t.Fatal(err)
			}
			store.write = func(path string, raw []byte) error {
				if afterWrite {
					if err := writeCreditFile(path, raw); err != nil {
						return err
					}
				}
				return ErrCreditDurability
			}
			ack := protocol.HourlyCreditAck{ReservationID: proof.Install.ReservationID, IssueSequence: proof.Install.IssueSequence, Digest: proof.Digest}
			if err = store.Ack(context.Background(), ack); !errors.Is(err, ErrCreditDurability) || store.Healthy() {
				t.Fatal("failed ACK was reported durable", err)
			}
			restarted, err := OpenCreditStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			proofs := restarted.Recovery()
			if !afterWrite && (len(proofs) != 1 || proofs[0] != proof) || afterWrite && len(proofs) != 0 {
				t.Fatal("uncertain ACK lost or rewrote immutable evidence", proofs)
			}
			if err = restarted.Ack(context.Background(), ack); err != nil {
				t.Fatal("master's exact ACK could not be replayed", err)
			}
			if _, err = restarted.Install(context.Background(), credit.install); !errors.Is(err, ErrCreditReplay) {
				t.Fatal("uncertain ACK restored spendable quota", err)
			}
		})
	}
}
