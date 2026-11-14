package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentShrinkAcknowledgmentAndOtherCreditWorkRespectNativeDrain(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	peer := f.peer(t)
	f.apply(t, peer)
	install := f.install(peer, "held-credit", 1)
	// Keep one byte of the handoff rate-bound: fully prepaid handoffs retain
	// their independent authority when a reduced-rate grant shrinks.
	install.ByteCeiling = 6
	if r := f.command(t, peer, "install-held", protocol.HourlyCreditInstallCommand, install); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	interrupted := make(chan struct{})
	flow, grant := f.grantedFlow(t, peer, func() { close(interrupted) })
	var p *hourly.Permit
	// The newly installed rate grant starts empty. Wait until the one reduced
	// byte is available, without admitting a shorter, fully prepaid handoff.
	await(t, func() bool {
		var err error
		p, _, err = flow.TryAcquire(hourly.Download, 7, 7)
		if err != nil {
			t.Fatal(err)
		}
		return p != nil
	})
	if err := p.Begin(); err != nil {
		t.Fatal(err)
	}
	defer p.Complete(hourly.Uncertain)
	// Force a fresh demand while the first native handoff remains unfinished.
	var probe *hourly.Permit
	await(t, func() bool {
		var err error
		probe, _, err = flow.TryAcquire(hourly.Upload, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		return probe != nil
	})
	probe.Complete(hourly.NotHandedOff)
	grant.Nonce = f.demand(t, peer, grant.Nonce).Nonce
	grant.Sequence = 2
	grant.RateBytesPerSecond = 500
	grant.BurstBytes = 8192
	for range 2 {
		peer.send(t, protocol.New("hourly.grant", "", 0, grant))
	}
	select {
	case <-interrupted:
	case <-time.After(3 * time.Second):
		t.Fatal("shrink did not interrupt native handoff")
	}
	heldResult := f.command(t, peer, "seal-held", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: "held-credit"})
	heldRaw, err := json.Marshal(heldResult.Data)
	var heldProof protocol.HourlyCreditProof
	if err != nil || heldResult.Status != "completed" || protocol.Decode(heldRaw, &heldProof) != nil || heldProof.AdmittedDownloadBytes != 6 || heldProof.UnusedBytes != 0 {
		t.Fatal("financial seal waited for or miscounted an admitted handoff", heldResult.Status, err)
	}
	// Another reservation can install, seal and acknowledge while the first
	// native rate barrier remains pending. Financial credit already settled.
	other := f.install(peer, "other-credit", 2)
	if r := f.command(t, peer, "install-other", protocol.HourlyCreditInstallCommand, other); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	r := f.command(t, peer, "seal-other", protocol.HourlyCreditSealCommand, protocol.HourlyCreditSeal{ReservationID: other.ReservationID})
	if r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	raw, err := json.Marshal(r.Data)
	if err != nil {
		t.Fatal(err)
	}
	var proof protocol.HourlyCreditProof
	if err = protocol.Decode(raw, &proof); err != nil {
		t.Fatal(err)
	}
	ack := protocol.HourlyCreditAck{ReservationID: other.ReservationID, IssueSequence: other.IssueSequence, Digest: proof.Digest}
	if r = f.command(t, peer, "ack-other", protocol.HourlyCreditAckCommand, ack); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	timer := time.NewTimer(200 * time.Millisecond)
checking:
	for {
		select {
		case event := <-f.audit:
			if event.peer != peer {
				continue
			}
			if event.message.Type == "hourly.grant.ack" {
				var a protocol.HourlyGrantAck
				if protocol.Decode(event.message.Data, &a) == nil && a.Sequence == 2 && a.Applied {
					t.Fatal("shrink ACK escaped native drain")
				}
			}
		case <-timer.C:
			break checking
		}
	}
	p.Complete(hourly.Uncertain)
	gotGrant := false
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for !gotGrant {
		select {
		case event := <-f.frames:
			if event.peer != peer {
				continue
			}
			if event.message.Type == "hourly.grant.ack" {
				var a protocol.HourlyGrantAck
				if protocol.Decode(event.message.Data, &a) == nil && a.Sequence == 2 && a.Applied {
					gotGrant = true
				}
			}
		case <-deadline.C:
			t.Fatal("native completion did not release the rate grant acknowledgment")
		}
	}
}
