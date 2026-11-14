package hourly

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func twoSealCandidates(t *testing.T) (*CreditStore, string, []SealCandidate) {
	t.Helper()
	store, path := openCreditFixture(t)
	var candidates []SealCandidate
	for i := uint64(1); i <= 2; i++ {
		install := creditFixtureInstall(i)
		install.ReservationID = fmt.Sprintf("batch-credit-%d", i)
		if i == 2 {
			install.Kind = "extra"
		}
		credit, err := store.Install(context.Background(), install)
		if err != nil || !credit.marker.claim() {
			t.Fatal("cannot prepare live credit", err)
		}
		candidates = append(candidates, SealCandidate{credit: credit, admitted: [2]uint64{i * 100, i * 50}, unused: 1000 - i*150})
	}
	return store, path, candidates
}

func TestSealBatchCommitsMaximumObligationsOnceAndReplaysExactly(t *testing.T) {
	store, path := openCreditFixture(t)
	// Construct a valid already-installed journal without making this boundary
	// regression perform 1,024 unrelated installation fsyncs.
	candidates := make([]SealCandidate, 0, creditJournalMaxObligations)
	for i := uint64(1); i <= creditJournalMaxObligations; i++ {
		install := creditFixtureInstall(i)
		install.ReservationID = fmt.Sprintf("credit-%04d", i)
		marker := newCreditMarker(store)
		if !marker.claim() {
			t.Fatal("fixture marker was already claimed")
		}
		credit := InstalledCredit{install: install, digest: protocol.HourlyInstallDigest(install), marker: marker}
		store.data.Records = append(store.data.Records, creditRecord{Install: install, Digest: credit.digest})
		store.markers[install.ReservationID] = marker
		candidates = append(candidates, SealCandidate{credit: credit, admitted: [2]uint64{123, 456}, unused: 421})
	}
	store.data.AgentID = candidates[0].credit.install.AgentID
	store.data.HighWater = creditJournalMaxObligations
	writeCreditFixture(t, path, store.data)
	writes := 0
	store.write = func(path string, raw []byte) error {
		writes++
		return writeCreditFile(path, raw)
	}
	proofs, err := store.SealBatch(context.Background(), candidates)
	if err != nil || len(proofs) != creditJournalMaxObligations || writes != 1 {
		t.Fatal("batch did not use exactly one durability barrier", len(proofs), writes, err)
	}
	for i, proof := range proofs {
		if proof.Install != candidates[i].credit.install || proof.AdmittedUploadBytes != 123 || proof.AdmittedDownloadBytes != 456 || proof.UnusedBytes != 421 || proof.UnknownBytes != 0 || proof.Recovery || protocol.ValidateHourlyProof(proof) != nil || candidates[i].credit.marker.active() {
			t.Fatal("batch changed scope, partition or activation", i, proof)
		}
	}
	if replay, err := store.SealBatch(context.Background(), candidates); err != nil || len(replay) != len(proofs) || writes != 1 {
		t.Fatal("identical batch replay rewrote the journal", writes, err)
	} else {
		for i := range proofs {
			if replay[i] != proofs[i] {
				t.Fatal("batch replay changed immutable proof", i)
			}
		}
	}
	_ = store.Close()
	reopened, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retained := reopened.Recovery()
	if len(retained) != len(proofs) {
		t.Fatal("restart lost batch proofs", len(retained))
	}
	for i := range retained {
		if retained[i] != proofs[i] {
			t.Fatal("restart changed a normal proof into unknown credit", i)
		}
	}
}

func TestSealBatchValidatesAllPartitionsBeforeWriting(t *testing.T) {
	for _, mode := range []string{"invalid-second", "zero-candidate", "duplicate", "changed-final"} {
		t.Run(mode, func(t *testing.T) {
			store, path, candidates := twoSealCandidates(t)
			var previous protocol.HourlyCreditProof
			if mode == "changed-final" {
				var err error
				previous, err = store.Seal(context.Background(), candidates[0])
				if err != nil {
					t.Fatal(err)
				}
				candidates[0].admitted[0]++
				candidates[0].unused--
				candidates[0], candidates[1] = candidates[1], candidates[0]
			} else if mode == "duplicate" {
				candidates[1] = candidates[0]
			} else if mode == "zero-candidate" {
				candidates[1] = SealCandidate{}
			} else {
				candidates[1].unused++
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if proofs, err := store.SealBatch(context.Background(), candidates); !errors.Is(err, ErrCreditScope) || len(proofs) != 0 {
				t.Fatal("invalid batch returned proofs", proofs, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || !store.Healthy() {
				t.Fatal("invalid batch partially committed or disabled valid credit", err)
			}
			retained := store.Recovery()
			if mode == "changed-final" {
				if len(retained) != 1 || retained[0] != previous {
					t.Fatal("batch rewrote a finalized proof", retained)
				}
			} else if len(retained) != 0 {
				t.Fatal("earlier candidate escaped failed batch validation", retained)
			}
		})
	}
}

func TestSealBatchDurabilityFailureNeverReturnsUncommittedProofs(t *testing.T) {
	for _, afterWrite := range []bool{false, true} {
		t.Run(fmt.Sprint("after-write-", afterWrite), func(t *testing.T) {
			store, path, candidates := twoSealCandidates(t)
			store.write = func(path string, raw []byte) error {
				if afterWrite {
					if err := writeCreditFile(path, raw); err != nil {
						return err
					}
				}
				return ErrCreditDurability
			}
			proofs, err := store.SealBatch(context.Background(), candidates)
			if !errors.Is(err, ErrCreditDurability) || len(proofs) != 0 || store.Healthy() {
				t.Fatal("failed barrier published financial success", proofs, err)
			}
			for _, candidate := range candidates {
				if candidate.credit.marker.active() {
					t.Fatal("failed durability retained admission authority")
				}
			}
			reopened, err := OpenCreditStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			retained := reopened.Recovery()
			if len(retained) != len(candidates) {
				t.Fatal("failed batch lost obligations", retained)
			}
			for i, proof := range retained {
				if proof.Install != candidates[i].credit.install {
					t.Fatal("failed batch changed original scope", proof)
				}
				if afterWrite {
					if proof.Recovery || proof.UnknownBytes != 0 || proof.AdmittedUploadBytes != candidates[i].admitted[0] || proof.AdmittedDownloadBytes != candidates[i].admitted[1] || proof.UnusedBytes != candidates[i].unused {
						t.Fatal("surviving atomic write was only partially sealed", proof)
					}
				} else if !proof.Recovery || proof.UnknownBytes != proof.Install.ByteCeiling || proof.UnusedBytes != 0 || proof.AdmittedUploadBytes != 0 || proof.AdmittedDownloadBytes != 0 {
					t.Fatal("missing barrier fabricated a reclaimable residual", proof)
				}
			}
		})
	}
}

func TestSealBatchCancellationPreservesUnsealedJournal(t *testing.T) {
	store, path, candidates := twoSealCandidates(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	store.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := store.SealBatch(ctx, candidates); done <- err }()
	cancel()
	store.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled batch crossed a durability barrier", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || len(store.Recovery()) != 0 {
		t.Fatal("cancelled batch changed retained evidence", err)
	}
	for _, candidate := range candidates {
		if !candidate.credit.marker.active() {
			t.Fatal("cancellation invalidated a still-unsealed live marker")
		}
	}
}
