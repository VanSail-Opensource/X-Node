package agent

import (
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentHourlyReconnectSealsOriginalScopeWithoutRestoringCredit(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	first := f.peer(t)
	f.apply(t, first)
	install := f.install(first, "old-credit", 1)
	if r := f.command(t, first, "install-old", protocol.HourlyCreditInstallCommand, install); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	flow, _ := f.grantedFlow(t, first, func() {})
	p, _, err := flow.TryAcquire(hourly.Upload, len([]byte("abc")), 1)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(hourly.Accepted)
	_ = first.socket.Close()
	second := f.peer(t)
	if second.session == "" || second.session == first.session {
		t.Fatal("reconnect reused control session")
	}
	await(t, func() bool { return f.a.Client.HourlySession() == second.session })
	await(t, func() bool {
		return len(f.a.hourly.store.Recovery()) == 1 && len(f.a.hourly.controller.CreditIDs()) == 0
	})
	proof := f.a.hourly.store.Recovery()[0]
	if proof.Install != install || proof.AdmittedUploadBytes != 3 || proof.UnusedBytes != 997 || proof.UnknownBytes != 0 {
		t.Fatal("reconnect lost original obligation", proof)
	}
	if len(f.a.hourly.controller.CreditIDs()) != 0 {
		t.Fatal("old session credit remained spendable")
	}
	stale := f.command(t, second, "old-session-refusal", protocol.HourlyCreditInstallCommand, install)
	if stale.Status != "failed" {
		t.Fatal("known stale-session refusal became uncertain", stale.Status, stale.Error)
	}
	if r := f.command(t, second, "install-new", protocol.HourlyCreditInstallCommand, f.install(second, "new-credit", 2)); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	var batch protocol.HourlyCreditProofBatch
	if err = protocol.Decode(f.frame(t, second, "hourly.credit.proofs", "").Data, &batch); err != nil || len(batch.Proofs) != 1 || batch.Proofs[0].Install.SessionID != first.session {
		t.Fatal("old scope proof did not replay over new connection", batch, err)
	}
}
