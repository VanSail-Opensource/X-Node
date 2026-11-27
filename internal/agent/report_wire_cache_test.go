package agent

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
)

func TestTrafficReplayReusesHeadWithoutSealingNewUsage(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Store: store, Client: transport.New("", "")}
	if err := store.AddTraffic(state.Traffic{1: {5, 7}}); err != nil {
		t.Fatal(err)
	}
	var cached protocol.Message
	if err := a.sendTrafficReport(&cached, true); err != nil || len(cached.Data) == 0 {
		t.Fatalf("first traffic report: %+v, %v", cached, err)
	}
	old := cached
	if err := store.AddTraffic(state.Traffic{1: {11, 13}}); err != nil {
		t.Fatal(err)
	}
	for _, seal := range []bool{true, false} {
		if err := a.sendTrafficReport(&cached, seal); err != nil || cached.ID != old.ID || len(cached.Data) == 0 || &cached.Data[0] != &old.Data[0] {
			t.Fatal("unchanged head was reencoded or replaced", err)
		}
	}
	if ok, err := store.Acknowledge(old.ID); err != nil || !ok {
		t.Fatal("head acknowledgement", ok, err)
	}
	if err := a.sendTrafficReport(&cached, false); err != nil || cached.ID != "" || len(cached.Data) != 0 {
		t.Fatal("replay selected an acknowledged head or sealed new traffic", err)
	}
	if err := a.sendTrafficReport(&cached, true); err != nil || cached.ID == "" || cached.ID == old.ID {
		t.Fatal("periodic report did not seal the new head", err)
	}
	var report protocol.TrafficReport
	if err := protocol.Decode(cached.Data, &report); err != nil || report.Traffic[1] != [2]uint64{11, 13} {
		t.Fatal("new report accounting", report.Traffic, err)
	}
}

func BenchmarkReplayUnacknowledgedTraffic(b *testing.B) {
	for _, cached := range []bool{false, true} {
		name := "clone_and_encode"
		if cached {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			store, err := state.Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			a := &Agent{Store: store, Client: transport.New("", "")}
			now := time.Now().UTC()
			traffic := make(state.Traffic, 2048)
			samples := make([]protocol.TrafficSample, 0, 2048)
			for id := 1; id <= 2048; id++ {
				traffic[id] = [2]uint64{123, 321}
				samples = append(samples, protocol.TrafficSample{UserID: id, AccountingPeriod: "billing-period", From: now.Add(-time.Second), Through: now, UploadBytes: 123, DownloadBytes: 321})
			}
			if err := store.AddAccounting(traffic, samples); err != nil {
				b.Fatal(err)
			}
			var wire protocol.Message
			if err := a.sendTrafficReport(&wire, true); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if cached {
					if err := a.sendTrafficReport(&wire, true); err != nil {
						b.Fatal(err)
					}
					continue
				}
				batch, err := store.Batch()
				if err != nil || batch == nil {
					b.Fatalf("report head: %v", err)
				}
				a.Client.Send(protocol.New("traffic.report", batch.ID, 0, batch), true)
			}
		})
	}
}
