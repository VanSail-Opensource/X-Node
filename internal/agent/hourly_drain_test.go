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
	if r := f.command(t, peer, "install-held", protocol.HourlyCreditInstallCommand, f.install(peer, "held-credit", 1)); r.Status != "completed" {
		t.Fatal(r.Status, r.Error)
	}
	interrupted := make(chan struct{})
	flow, grant := f.grantedFlow(t, peer, func() { close(interrupted) })
	p, _, err := flow.TryAcquire(hourly.Download, len([]byte("pending")), 1)
	if err != nil || p == nil {
		t.Fatal(err)
	}
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	defer p.Complete(hourly.Uncertain)
	// Force a fresh demand while the first native handoff remains unfinished.
	probe, _, err := flow.TryAcquire(hourly.Upload, 1, 1)
	if err != nil || probe == nil {
		t.Fatal(err)
	}
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
	peer.send(t, protocol.New("command", "seal-held", 0, map[string]any{"name": protocol.HourlyCreditSealCommand, "args": protocol.HourlyCreditSeal{ReservationID: "held-credit"}}))
	f.frame(t, peer, "command.accepted", "seal-held")
	// Another reservation can install, seal and acknowledge while the first
	// native barrier remains pending; no global runtime lock may wait on it.
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
			if event.message.Type == "command.result" && event.message.ID == "seal-held" {
				t.Fatal("seal escaped native drain")
			}
		case <-timer.C:
			break checking
		}
	}
	p.Complete(hourly.Uncertain)
	gotGrant, gotSeal := false, false
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	for !gotGrant || !gotSeal {
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
			if event.message.Type == "command.result" && event.message.ID == "seal-held" {
				var result JobResult
				if protocol.Decode(event.message.Data, &result) != nil || result.Status != "completed" {
					t.Fatal("held seal failed", result.Status)
				}
				gotSeal = true
			}
		case <-deadline.C:
			t.Fatal("native completion did not release grant/seal acknowledgments")
		}
	}
}
