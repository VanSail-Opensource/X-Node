package state

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestHourlyHistoryCapacityLeavesNativeBankAndWireBoundsIntact(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	samples := make([]protocol.HourlySample, MaxHourlyTrafficEntries+1)
	for i := range samples {
		samples[i] = hourlyHistoryFixture()
		samples[i].CounterGeneration = uint64(i + 1)
	}
	if err = store.AddAccountingWithHourly(Traffic{7: {10, 0}}, nil, samples); err != nil {
		t.Fatal(err)
	}
	if err = store.AddAccounting(Traffic{8: {20, 0}}, nil); err != nil {
		t.Fatal("history consumed native accumulation space", err)
	}
	batch, err := store.Batch()
	if err != nil || len(batch.HourlySamples) != MaxHourlyTrafficEntries || batch.DroppedHourlySamples != 1 || batch.Traffic[7][0] != 10 || batch.Traffic[8][0] != 20 {
		t.Fatal("history capacity changed native billing or hid coverage loss", err)
	}
	raw, err := json.Marshal(batch)
	if err != nil || len(raw)+4096 > protocol.MaxFrameBytes {
		t.Fatal("bounded history cannot fit the existing report transport", len(raw), err)
	}
}

func TestHourlyAdmissionHistoryNeverEntersDurableState(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	history := hourlyHistoryFixture()
	if err = store.AddAccountingWithHourly(nil, nil, []protocol.HourlySample{history}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Batch(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(store.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("hourly history was persisted", err)
	}
	if err = store.Authorize([]protocol.User{{ID: 1, UUID: "credential", AccountingPeriod: "paid", InboundTags: []string{"in"}}}, 1); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(store.path)
	if err != nil || bytes.Contains(after, []byte("hourly_samples")) || bytes.Contains(after, []byte("counter_generation")) {
		t.Fatal("configuration update serialized admission history", err)
	}
	restarted, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := restarted.Batch(); err != nil || batch != nil {
		t.Fatal("restart restored volatile usage history", batch, err)
	}
}
