package agent

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentAbsenceBarrierFencesAReservedButNeverIssuedCredit(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	f.apply(t, peer)
	expected := f.install(peer, "not-delivered", 1)
	result := f.command(t, peer, "prove-absence", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: expected.ReservationID, Expected: &expected})
	if result.Status != "completed" {
		t.Fatal("absence barrier failed", result.Status, result.Error)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	var proof protocol.HourlyCreditProof
	if err = protocol.Decode(raw, &proof); err != nil {
		t.Fatal(err)
	}
	if protocol.ValidateHourlyProof(proof) != nil || proof.Install != expected || proof.UnusedBytes != expected.ByteCeiling || proof.Recovery {
		t.Fatal("absence barrier invented an uncertain or different partition")
	}
	result = f.command(t, peer, "late-install", protocol.HourlyCreditInstallCommand, expected)
	if result.Status != "failed" {
		t.Fatal("late install reused returned credit", result.Status)
	}
}
