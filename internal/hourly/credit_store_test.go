package hourly

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestDurableInstallReplayCannotMintAnotherActivation(t *testing.T) {
	store, _ := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	var activated atomic.Int64
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			replay, err := store.Install(context.Background(), credit.install)
			if err != nil || replay.marker != credit.marker {
				t.Errorf("replayed install changed authority: %v", err)
				return
			}
			if replay.marker.claim() {
				activated.Add(1)
			}
		})
	}
	wg.Wait()
	if activated.Load() != 1 || !credit.marker.active() || len(store.data.Records) != 1 {
		t.Fatal("installation replay minted duplicate quota", activated.Load())
	}
}

func TestInstallCannotChangeAnyOriginalObligationScope(t *testing.T) {
	store, _ := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	for _, field := range []string{"owner", "generation", "day", "agent", "boot", "session", "ceiling", "kind", "sequence"} {
		t.Run(field, func(t *testing.T) {
			altered := credit.install
			switch field {
			case "owner":
				altered.Owner.ID = "another"
			case "generation":
				altered.Owner.Generation++
			case "day":
				altered.DayUTC = "2026-11-10"
			case "agent":
				altered.AgentID = altered.BootID
			case "boot":
				altered.BootID = altered.AgentID
			case "session":
				altered.SessionID = altered.AgentID
			case "ceiling":
				altered.ByteCeiling++
			case "kind":
				altered.Kind = "extra"
			case "sequence":
				altered.IssueSequence++
			}
			if _, err := store.Install(context.Background(), altered); !errors.Is(err, ErrCreditScope) {
				t.Fatal("changed obligation accepted", err)
			}
		})
	}
	fresh := credit.install
	fresh.ReservationID = "different"
	if _, err := store.Install(context.Background(), fresh); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("highwater permitted an old issue sequence", err)
	}
	fresh.IssueSequence++
	fresh.AgentID = fresh.BootID
	if _, err := store.Install(context.Background(), fresh); !errors.Is(err, ErrCreditScope) {
		t.Fatal("journal was reused for another persistent agent", err)
	}
}

func TestSealAndAckRequireExactPartitionAndFinalDigest(t *testing.T) {
	store, path := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	if !credit.marker.claim() {
		t.Fatal("durable credit unavailable")
	}
	candidate := SealCandidate{credit: credit, admitted: [2]uint64{200, 300}, unused: 500}
	proof, err := store.Seal(context.Background(), candidate)
	if err != nil || protocol.ValidateHourlyProof(proof) != nil || credit.marker.active() {
		t.Fatal("confirmed partition was not sealed", proof, err)
	}
	replay, err := store.Seal(context.Background(), candidate)
	if err != nil || replay != proof {
		t.Fatal("seal replay changed a final proof", replay, err)
	}
	candidate.admitted[0]++
	candidate.unused--
	if _, err = store.Seal(context.Background(), candidate); !errors.Is(err, ErrCreditScope) {
		t.Fatal("final evidence was rewritten", err)
	}
	ack := protocol.HourlyCreditAck{ReservationID: proof.Install.ReservationID, IssueSequence: 1, Digest: proof.Digest}
	wrong := ack
	wrong.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
	if err = store.Ack(context.Background(), wrong); !errors.Is(err, ErrCreditScope) || len(store.Recovery()) != 1 {
		t.Fatal("nonmatching ACK discarded an obligation", err)
	}
	if err = store.Ack(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if err = store.Ack(context.Background(), ack); err != nil || len(store.Recovery()) != 0 {
		t.Fatal("identical ACK was not idempotent", err)
	}
	restarted, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if _, err = restarted.Install(context.Background(), credit.install); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("ACKed credit became spendable after restart", err)
	}
}
