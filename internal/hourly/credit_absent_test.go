package hourly

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAbsentCreditProofIsDurableIdempotentAndCannotActivate(t *testing.T) {
	store, path := openCreditFixture(t)
	expected := creditFixtureInstall(2)
	proof, err := store.SealAbsent(context.Background(), expected)
	if err != nil || proof.UnusedBytes != expected.ByteCeiling || proof.UnknownBytes != 0 || proof.Recovery || proof.Digest != protocol.HourlyProofDigest(proof) {
		t.Fatal(proof, err)
	}
	if len(store.markers) != 0 {
		t.Fatal("absence proof created an installable marker")
	}
	if replay, err := store.SealAbsent(context.Background(), expected); err != nil || replay != proof {
		t.Fatal("absence replay changed proof", replay, err)
	}
	if _, err = store.Install(context.Background(), expected); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("absent proof later activated", err)
	}
	reopened, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if replay, err := reopened.SealAbsent(context.Background(), expected); err != nil || replay != proof {
		t.Fatal("restart changed absence proof", replay, err)
	}
	ack := protocol.HourlyCreditAck{ReservationID: expected.ReservationID, IssueSequence: expected.IssueSequence, Digest: proof.Digest}
	if err = reopened.Ack(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	if replay, err := reopened.SealAbsent(context.Background(), expected); err != nil || replay != proof {
		t.Fatal("exact unused tombstone could not replay", err)
	}
}

func TestAbsentReorderedGapAboveRetirementFloorRemainsProvable(t *testing.T) {
	store, path := openCreditFixture(t)
	newer := creditFixtureInstall(2)
	newer.ReservationID = "newer-credit"
	if _, err := store.Install(context.Background(), newer); err != nil {
		t.Fatal(err)
	}
	older := creditFixtureInstall(1)
	older.ReservationID = "missing-older-credit"
	proof, err := store.SealAbsent(context.Background(), older)
	if err != nil || proof.UnusedBytes != older.ByteCeiling || store.data.HighWater != 2 {
		t.Fatal("reordered unseen sequence remained stuck", proof, err)
	}
	if store.data.Records[0].Install != older || store.data.Records[1].Install != newer {
		t.Fatal("absence insertion broke issue ordering")
	}
	reopened, err := OpenCreditStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.Install(context.Background(), older); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("reordered absent install replayed", err)
	}
}

func TestAbsenceCannotBypassActiveCreditOrKnownSequenceScope(t *testing.T) {
	store, _ := openCreditFixture(t)
	expected := creditFixtureInstall(1)
	credit, err := store.Install(context.Background(), expected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.SealAbsent(context.Background(), expected); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("active obligation bypassed controller freeze", err)
	}
	if !credit.marker.claim() || !credit.marker.active() {
		t.Fatal("rejected absence invalidated live marker")
	}
	changed := expected
	changed.Owner.Generation++
	if _, err = store.SealAbsent(context.Background(), changed); !errors.Is(err, ErrCreditScope) {
		t.Fatal("changed owner accepted", err)
	}
	changed = expected
	changed.ReservationID = "different-reservation"
	if _, err = store.SealAbsent(context.Background(), changed); !errors.Is(err, ErrCreditScope) {
		t.Fatal("known issue sequence relabeled", err)
	}
	changed = expected
	changed.IssueSequence = 2
	changed.ReservationID = "foreign-agent"
	changed.AgentID = expected.BootID
	if _, err = store.SealAbsent(context.Background(), changed); !errors.Is(err, ErrCreditScope) {
		t.Fatal("foreign persistent agent accepted", err)
	}
	if len(store.Recovery()) != 0 || store.data.HighWater != 1 {
		t.Fatal("rejected absence rewrote live obligation")
	}
	actual, err := store.Seal(context.Background(), SealCandidate{credit: credit, admitted: [2]uint64{100, 0}, unused: 900})
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := store.SealAbsent(context.Background(), expected); err != nil || replay != actual {
		t.Fatal("absence replay rewrote known admitted partition", replay, err)
	}
	if err = store.Ack(context.Background(), protocol.HourlyCreditAck{ReservationID: expected.ReservationID, IssueSequence: expected.IssueSequence, Digest: actual.Digest}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.SealAbsent(context.Background(), expected); !errors.Is(err, ErrCreditReplay) {
		t.Fatal("used tombstone was guessed unused", err)
	}
}
