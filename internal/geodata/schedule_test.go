package geodata

import (
	"encoding/json"
	"testing"
	"time"
)

func TestHourIntervalAndLegacySchedule(t *testing.T) {
	now := time.Date(2026, 10, 17, 10, 15, 0, 0, time.UTC)
	for _, test := range []struct {
		name, document string
		next           time.Time
		invalid        bool
	}{
		{"hours", `{"geodata":{"interval_hours":24,"assets":[]}}`, now.Add(24 * time.Hour), false},
		{"disabled", `{"geodata":{"interval_hours":0,"assets":[]}}`, time.Time{}, false},
		{"legacy", `{"geodata":{"cron":"0 * * * *","assets":[]}}`, time.Date(2026, 10, 17, 11, 0, 0, 0, time.UTC), false},
		{"conflict", `{"geodata":{"cron":"0 * * * *","interval_hours":24}}`, time.Time{}, true},
		{"geoip", `{"geodata":{"assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}}`, time.Time{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := FromNative(json.RawMessage(test.document))
			if (err != nil) != test.invalid {
				t.Fatalf("validation=%v", err)
			}
			if !test.invalid && !Next(policy, now).Equal(test.next) {
				t.Fatalf("next=%v", Next(policy, now))
			}
		})
	}
}
