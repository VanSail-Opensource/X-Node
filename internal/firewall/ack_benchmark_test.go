package firewall

import "testing"

func BenchmarkDuplicateFirewallAcknowledgment(b *testing.B) {
	for _, method := range []string{"journal", "skip"} {
		b.Run(method, func(b *testing.B) {
			guard, err := OpenGuard(b.TempDir(), nil)
			if err != nil {
				b.Fatal(err)
			}
			ids := []string{"already-acknowledged"}
			b.ResetTimer()
			for range b.N {
				if method == "journal" {
					err = guard.appendJournal(journalRecord{Ack: ids})
				} else {
					err = guard.acknowledge(ids)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
