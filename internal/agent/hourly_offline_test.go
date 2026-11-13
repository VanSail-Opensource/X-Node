package agent

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAgentMasterOutagePreservesReservedCreditUntilSuccessfulReconnect(t *testing.T) {
	f := newHourlyAgentFixture(t, true, false)
	first := f.peer(t)
	f.apply(t, first)
	install := f.install(first, "offline-credit", 1)
	if result := f.command(t, first, "install-offline", protocol.HourlyCreditInstallCommand, install); result.Status != "completed" {
		t.Fatal(result.Status, result.Error)
	}
	flow, _ := f.grantedFlow(t, first, func() {})
	f.offline.Store(true)
	_ = first.socket.Close()
	await(t, func() bool { return !f.a.Client.Hourly() })
	// Cross the credit-retirement interval and a refused reconnect. Neither
	// event is financial evidence that an installed reservation was unused.
	<-time.After(1200 * time.Millisecond)
	if f.a.Client.HourlyAuthoritySession() != first.session || len(f.a.hourly.store.Recovery()) != 0 {
		t.Fatal("temporary outage retired locally accepted authority")
	}
	p, _, err := flow.TryAcquire(hourly.Download, 23, 1)
	if err != nil || p == nil || p.Bytes() != 23 {
		t.Fatal("reserved credit became unavailable during master outage", err)
	}
	if err = p.Begin(); err != nil {
		t.Fatal(err)
	}
	p.Complete(hourly.Uncertain)
	f.offline.Store(false)
	second := f.peer(t)
	await(t, func() bool {
		return f.a.Client.HourlySession() == second.session && len(f.a.hourly.store.Recovery()) == 1
	})
	proof := f.a.hourly.store.Recovery()[0]
	if proof.Install != install || proof.AdmittedDownloadBytes != 23 || proof.UnusedBytes != 977 || proof.UnknownBytes != 0 {
		t.Fatal("master restart lost exact offline credit settlement", proof)
	}
}
