package hourly

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSealUnclaimedCannotRefundAnActivatedCredit(t *testing.T) {
	for _, activated := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected-before-controller", true: "controller-claimed"}[activated], func(t *testing.T) {
			store, _ := openCreditFixture(t)
			credit := installCreditFixture(t, store)
			if activated && !credit.marker.claim() {
				t.Fatal("activation unavailable")
			}
			proof, err := store.SealUnclaimed(context.Background(), credit)
			if activated {
				if !errors.Is(err, ErrCreditReplay) || proof.Digest != "" || !credit.marker.active() || len(store.Recovery()) != 0 {
					t.Fatal("activated quota was incorrectly declared unused", proof, err)
				}
				return
			}
			if err != nil || proof.UnusedBytes != 1000 || proof.UnknownBytes != 0 || protocol.ValidateHourlyProof(proof) != nil || credit.marker.active() || credit.marker.claim() {
				t.Fatal("known-unused install was not durably fenced", proof, err)
			}
		})
	}
}

func TestUnclaimedSealAndControllerActivationHaveOneWinner(t *testing.T) {
	store, _ := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	start := make(chan struct{})
	activated := make(chan bool, 1)
	go func() {
		<-start
		activated <- credit.marker.claim()
	}()
	close(start)
	proof, err := store.SealUnclaimed(context.Background(), credit)
	if <-activated {
		if !errors.Is(err, ErrCreditReplay) || proof.Digest != "" {
			t.Fatal("activation raced a successful unused proof", proof, err)
		}
	} else if err != nil || proof.UnusedBytes != credit.install.ByteCeiling {
		t.Fatal("unused fence lost its financial proof", proof, err)
	}
}

func TestCancelledUnclaimedSealLeavesAuthorityUnclaimed(t *testing.T) {
	store, _ := openCreditFixture(t)
	credit := installCreditFixture(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.SealUnclaimed(ctx, credit); !errors.Is(err, context.Canceled) || !credit.marker.claim() {
		t.Fatal("cancelled attempt consumed activation authority", err)
	}
}
