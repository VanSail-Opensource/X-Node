package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestHourlyHistoryMetadataUsesDecimalStringsAndOptionalExtension(t *testing.T) {
	legacy := TrafficReport{ID: "agent:1", Traffic: Traffic{7: {1, 2}}}
	raw, err := json.Marshal(legacy)
	if err != nil || bytes.Contains(raw, []byte("hourly")) {
		t.Fatal("legacy report acquired unnegotiated hourly fields", string(raw), err)
	}
	at := time.Now().UTC()
	legacy.DroppedHourlySamples = ^uint64(0)
	legacy.HourlySamples = []HourlySample{{Owner: HourlyOwner{ID: "account", Generation: 1}, CounterGeneration: 2, EnrollmentID: "enrollment", UserID: 7, AccountingPeriod: "paid", DayUTC: at.Format(time.DateOnly), From: at, Through: at, UploadBytes: 9007199254740993}}
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"dropped_hourly_samples":"18446744073709551615"`, `"counter_generation":"2"`, `"upload_bytes":"9007199254740993"`} {
		if !bytes.Contains(raw, []byte(expected)) {
			t.Fatal("hourly history lost integer precision", string(raw))
		}
	}
	var decoded TrafficReport
	if err = json.Unmarshal(raw, &decoded); err != nil || len(decoded.HourlySamples) != 1 || decoded.HourlySamples[0] != legacy.HourlySamples[0] || decoded.DroppedHourlySamples != legacy.DroppedHourlySamples {
		t.Fatal("hourly history did not round-trip exactly", err)
	}
}
