package agent

import "testing"

func BenchmarkMasterCommandArguments(b *testing.B) {
	for name, raw := range map[string][]byte{
		"empty":   []byte(`{}`),
		"regular": []byte(`{"subject":{"user_id":1000,"accounting_period":"period"},"ips":["192.0.2.1","2001:db8::1"],"replace":true}`),
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := canonicalCommandArgs(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
