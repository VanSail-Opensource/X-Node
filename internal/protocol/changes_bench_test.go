package protocol

import (
	"encoding/json"
	"fmt"
	"testing"
)

func benchmarkNativeConfig() Config {
	c := Config{
		Xray:  json.RawMessage(`{"inbounds":[{"tag":"paid","protocol":"vless"}],"outbounds":[{"tag":"direct","protocol":"freedom"}],"geodata":{"interval_hours":24}}`),
		Users: make([]User, 600),
	}
	for i := range c.Users {
		c.Users[i] = User{
			ID: i + 1, UUID: fmt.Sprintf("account-%d", i+1), InboundTags: []string{"paid"},
			Credentials:    map[string]json.RawMessage{"paid": json.RawMessage(`{"limit":9007199254740993,"mode":"sample"}`)},
			SpeedLimitMbps: 100, AccountingPeriod: "current",
		}
	}
	return c
}

func BenchmarkClassifyUserControls(b *testing.B) {
	old := benchmarkNativeConfig()
	next := Clone(old)
	for i := range next.Users {
		next.Users[i].BlockNew = i%2 == 0
	}
	b.ReportAllocs()
	for b.Loop() {
		if changes := Classify(old, next); changes.Native || !changes.Registry {
			b.Fatal(changes)
		}
	}
}

func BenchmarkNativeIdentity(b *testing.B) {
	c := benchmarkNativeConfig()
	b.ReportAllocs()
	for b.Loop() {
		if len(NativeIdentity(c)) == 0 {
			b.Fatal("empty identity")
		}
	}
}
