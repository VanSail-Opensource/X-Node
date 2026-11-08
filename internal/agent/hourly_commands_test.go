package agent

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (f *hourlyAgentFixture) grantedFlow(t *testing.T, peer *hourlyTestPeer, interrupt func()) (*hourly.Flow, protocol.HourlyGrant) {
	t.Helper()
	u := f.config.Users[0]
	flow, err := f.a.hourly.controller.OpenFlow(hourly.BindingKey{Owner: hourly.OwnerKey{ID: u.Hourly.Owner.ID, Generation: u.Hourly.Owner.Generation}, EnrollmentID: u.Hourly.EnrollmentID, PrincipalID: u.ID, PeriodID: u.AccountingPeriod}, interrupt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(flow.Close)
	if p, _, err := flow.TryAcquire(hourly.Upload, 1, 1); err != nil || p != nil {
		t.Fatal("fresh flow bypassed absent grant", err)
	}
	demand := f.demand(t, peer, "")
	g := protocol.HourlyGrant{SessionID: peer.session, Owner: u.Hourly.Owner, Nonce: demand.Nonce, Sequence: 1, DayUTC: f.install(peer, "unused", 1).DayUTC, LifetimeMillis: 10000, RateBytesPerSecond: 1000, BurstBytes: 16384}
	peer.send(t, protocol.New("hourly.grant", "", 0, g))
	var ack protocol.HourlyGrantAck
	if err = protocol.Decode(f.frame(t, peer, "hourly.grant.ack", "").Data, &ack); err != nil || !ack.Applied || ack.Sequence != 1 {
		t.Fatal("grant not acknowledged", ack, err)
	}
	return flow, g
}

func TestAgentHourlyInstallSealAcknowledgmentAndReplay(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	f.apply(t, peer)
	install := f.install(peer, "credit-a", 1)
	if result := f.command(t, peer, "install-a", protocol.HourlyCreditInstallCommand, install); result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	flow, _ := f.grantedFlow(t, peer, func() {})
	payload := []byte("abc")
	p, _, err := flow.TryAcquire(hourly.Download, len(payload), 1)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(hourly.Uncertain)
	if result := f.command(t, peer, "install-replay", protocol.HourlyCreditInstallCommand, install); result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	progress := f.a.hourly.controller.CreditProgress(1)
	if len(progress) != 1 || progress[0].AdmittedDownloadBytes != 3 {
		t.Fatal("replay changed admitted quota", progress)
	}
	result := f.command(t, peer, "seal-a", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: install.ReservationID})
	if result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	raw, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	var proof protocol.HourlyCreditProof
	if err = protocol.Decode(raw, &proof); err != nil || proof.AdmittedDownloadBytes != 3 || proof.UnusedBytes != 997 || proof.UnknownBytes != 0 {
		t.Fatal(proof, err)
	}
	if result = f.command(t, peer, "seal-replay", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: install.ReservationID}); result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	ack := protocol.HourlyCreditAck{ReservationID: install.ReservationID, IssueSequence: install.IssueSequence, Digest: proof.Digest}
	for _, id := range []string{"ack-a", "ack-replay"} {
		if result = f.command(t, peer, id, protocol.HourlyCreditAckCommand, ack); result.Status != "completed" {
			t.Fatal(result.Status, result.Error)
		}
	}
	if len(f.a.hourly.store.Recovery()) != 0 || len(f.a.hourly.controller.CreditIDs()) != 0 {
		t.Fatal("acknowledged obligation remained active")
	}
}
