package agent

import (
	"fmt"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestHourlyCaptureRetryKeepsBothBaselinesUntilAtomicAcceptance(t *testing.T) {
	process, controller, flow, _, _ := captureHourlyFixture(t)
	admitHourlyCapture(t, flow, hourly.Upload, 7)
	if err := process.Store.AddTraffic(state.Traffic{1: {^uint64(0), 0}}); err != nil {
		t.Fatal(err)
	}
	current := state.Traffic{1: {10, 0}}
	if err := process.captureTrafficFrom(current); err == nil {
		t.Fatal("native counter overflow accepted")
	}
	if len(process.previous)+len(process.previousHourly) != 0 || len(controller.Samples()) != 1 {
		t.Fatal("failed capture advanced baselines or pruned hourly counters")
	}
	if _, err := process.Store.Flush(); err != nil {
		t.Fatal(err)
	}
	previous, err := process.Store.Batch()
	if err != nil || previous == nil || len(previous.HourlySamples) != 0 {
		t.Fatal("failed capture partially appended hourly samples", previous, err)
	}
	if err = process.Store.Ack(previous.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = process.captureTrafficFrom(current); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := process.Store.Batch()
	if err != nil || batch.Traffic[1][0] != 10 || len(batch.HourlySamples) != 1 || batch.HourlySamples[0].UploadBytes != 7 {
		t.Fatal("capture retry lost or duplicated admitted/native bytes", batch, err)
	}
}

func TestHourlyReadmissionUsesFreshGenerationWithoutInventingHistory(t *testing.T) {
	for _, fresh := range []int{1, 7, 15} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			process, controller, flow, key, now := captureHourlyFixture(t)
			admitHourlyCapture(t, flow, hourly.Upload, 7)
			if err := process.captureTrafficFrom(state.Traffic{1: {7, 0}}); err != nil {
				t.Fatal(err)
			}
			original := controller.Samples()[0].CounterGeneration
			if !controller.ApplyAuthorization(2, 2, nil) {
				t.Fatal("revocation rejected")
			}
			flow.Close()
			if err := process.captureTrafficFrom(state.Traffic{1: {7, 0}}); err != nil || len(controller.Samples()) != 0 {
				t.Fatal("accepted obsolete sample was not pruned", err)
			}
			if !controller.ApplyAuthorization(3, 3, []hourly.Authorization{{Key: key, PaidThrough: now.Add(time.Hour)}}) {
				t.Fatal("readmission rejected")
			}
			freshFlow, err := controller.OpenFlow(key, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer freshFlow.Close()
			admitHourlyCapture(t, freshFlow, hourly.Upload, fresh)
			if samples := controller.Samples(); len(samples) != 1 || samples[0].CounterGeneration == original {
				t.Fatal("readmission reused a cumulative baseline", samples)
			}
			for range 2 {
				if err = process.captureTrafficFrom(state.Traffic{1: {uint64(7 + fresh), 0}}); err != nil {
					t.Fatal(err)
				}
			}
			batch, err := process.Store.Batch()
			if err != nil || batch == nil {
				t.Fatal("missing accepted accounting report", err)
			}
			var admitted uint64
			for _, sample := range batch.HourlySamples {
				admitted += sample.UploadBytes
			}
			if err != nil || admitted != uint64(7+fresh) || batch.Traffic[1][0] != uint64(7+fresh) {
				t.Fatal("readmission lost or replayed historical usage", batch, err)
			}
		})
	}
}
