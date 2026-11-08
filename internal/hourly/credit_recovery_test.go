package hourly

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestRestartRetainsUnknownCreditAndOriginalControlSession(t *testing.T) {
	store, path := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	if !credit.marker.claim() {
		t.Fatal("activation unavailable")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	proofs := restarted.Recovery()
	if len(proofs) != 1 || proofs[0].Install != credit.install || !proofs[0].Recovery || proofs[0].UnknownBytes != 1000 || proofs[0].UnusedBytes != 0 || proofs[0].AdmittedUploadBytes != 0 || protocol.ValidateHourlyProof(proofs[0]) != nil {
		t.Fatal("restart fabricated consumption, unused quota or a new scope", proofs)
	}
	if _, err = restarted.Install(context.Background(), credit.install); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("recovery reactivated an old session", err)
	}
	again, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if recovered := again.Recovery(); len(recovered) != 1 || recovered[0] != proofs[0] {
		t.Fatal("repeated recovery changed final evidence", recovered)
	}
}

func TestFailedDurabilityNeverReturnsFreshAuthority(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "after-rename-barrier"}[afterWrite], func(t *testing.T) {
			store, path := openCreditFixture(t)
			first := installCreditFixture(t, store)
			if !first.marker.claim() {
				t.Fatal("activation unavailable")
			}
			store.write = func(path string, raw []byte) error {
				if afterWrite {
					if err := writeCreditFile(path, raw); err != nil {
						return err
					}
				}
				return ErrCreditDurability
			}
			second := first.install
			second.ReservationID, second.IssueSequence = "second", 2
			credit, err := store.Install(context.Background(), second)
			if !errors.Is(err, ErrCreditDurability) || credit.marker != nil || store.Healthy() || first.marker.active() {
				t.Fatal("failed barrier returned active credit", err)
			}
			restarted, err := OpenCreditStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			want := 1
			if afterWrite {
				want = 2
			}
			if proofs := restarted.Recovery(); len(proofs) != want {
				t.Fatal("uncertain durability lost financial obligations", proofs)
			}
		})
	}
}

func TestFailedSealLeavesResidualUnknownInsteadOfReclaimable(t *testing.T) {
	store, path := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	if !credit.marker.claim() {
		t.Fatal("activation unavailable")
	}
	store.write = func(string, []byte) error { return ErrCreditDurability }
	if proof, err := store.Seal(context.Background(), SealCandidate{credit: credit, admitted: [2]uint64{300, 200}, unused: 500}); !errors.Is(err, ErrCreditDurability) || proof.Digest != "" {
		t.Fatal("failed seal exposed uncommitted unused proof", proof, err)
	}
	restarted, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if proofs := restarted.Recovery(); len(proofs) != 1 || proofs[0].UnknownBytes != 1000 || proofs[0].UnusedBytes != 0 {
		t.Fatal("failed seal credited an unproven residual", proofs)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credit evidence is not private", err)
	}
}
