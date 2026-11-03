package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestActivityHistoryRoundTripsBothTelemetryFormats(t *testing.T) {
	at := time.Now().UTC()
	r := TelemetryReport{Users: UserMetrics{SampledAt: &at, ActiveIPObservations: []IPActivity{{7, "2001:4860::8", at, 9007199254740993}}, ObservationDrops: 9007199254740995}}
	for _, compact := range []bool{false, true} {
		var value any = r
		if compact {
			value = CompactTelemetry(r)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded TelemetryReport
		if compact {
			var c CompactTelemetryReport
			err = Decode(raw, &c)
			if err == nil {
				decoded, err = ExpandTelemetry(c)
			}
		} else {
			err = Decode(raw, &decoded)
		}
		if err != nil || ValidateActivity(decoded.Users) != nil || decoded.Users.ObservationDrops != r.Users.ObservationDrops || len(decoded.Users.ActiveIPObservations) != 1 || decoded.Users.ActiveIPObservations[0] != r.Users.ActiveIPObservations[0] {
			t.Fatal("observation precision or empty-user history lost", compact, decoded, err)
		}
	}
}

func TestInvalidActivityHistoryIsRejected(t *testing.T) {
	at := time.Now().UTC()
	valid := IPActivity{7, "8.8.8.8", at, 1}
	for _, metrics := range []UserMetrics{
		{ActiveIPObservations: []IPActivity{valid}},
		{SampledAt: &at, ActiveIPObservations: []IPActivity{valid, valid}},
		{SampledAt: &at, ActiveIPObservations: []IPActivity{{7, "invalid", at, 1}}},
		{SampledAt: &at, ActiveIPObservations: []IPActivity{{7, "8.8.8.8", at.Add(time.Second), 1}}},
		{SampledAt: &at, ActiveIPObservations: make([]IPActivity, MaxActivityObservations+1)},
	} {
		if ValidateActivity(metrics) == nil {
			t.Fatal("invalid activity evidence accepted")
		}
	}
	schema := Schema(IPActivity{})["properties"].(map[string]any)["observations"].(map[string]any)
	if schema["type"] != "string" {
		t.Fatal("schema loses decimal-string counter precision", schema)
	}
}
