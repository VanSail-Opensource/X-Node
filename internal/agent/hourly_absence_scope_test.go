package agent

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentExpectedScopeRefusalCannotFreezeOrSealInstalledCredit(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	f.apply(t, peer)
	install := f.install(peer, "live-credit", 1)
	if result := f.command(t, peer, "install-live", protocol.HourlyCreditInstallCommand, install); result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	changes := []struct {
		name   string
		mutate func(*protocol.HourlyCreditInstall)
	}{
		{"owner", func(i *protocol.HourlyCreditInstall) { i.Owner.Generation++ }},
		{"ceiling", func(i *protocol.HourlyCreditInstall) { i.ByteCeiling++ }},
		{"reservation", func(i *protocol.HourlyCreditInstall) { i.ReservationID = "other-credit" }},
		{"agent", func(i *protocol.HourlyCreditInstall) { i.AgentID = "ffffffffffffffffffffffffffffffff" }},
	}
	for _, change := range changes {
		expected := install
		change.mutate(&expected)
		result := f.command(t, peer, "reject-"+change.name, protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: install.ReservationID, Expected: &expected})
		if result.Status != "failed" {
			t.Fatal("scope refusal was not proven pre-mutation", change.name, result.Status)
		}
		if ids := f.a.hourly.controller.CreditIDs(); len(ids) != 1 || ids[0] != install.ReservationID || len(f.a.hourly.store.Recovery()) != 0 {
			t.Fatal("mismatched expectation changed an obligation", change.name)
		}
	}
	flow, _ := f.grantedFlow(t, peer, func() {})
	p, _, err := flow.TryAcquire(hourly.Upload, 3, 1)
	if err != nil || p == nil {
		t.Fatal("scope refusal froze usable credit", err)
	}
	if err = p.Begin(); err != nil {
		t.Fatal("scope refusal revoked original credit", err)
	}
	p.Complete(hourly.Accepted)
	result := f.command(t, peer, "seal-live", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: install.ReservationID, Expected: &install})
	if result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	var proof protocol.HourlyCreditProof
	if err = protocol.Decode(raw, &proof); err != nil || proof.Install != install || proof.AdmittedUploadBytes != 3 || proof.UnusedBytes != 997 {
		t.Fatal("scope refusals changed final accounting", proof, err)
	}
}
