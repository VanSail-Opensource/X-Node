//go:build linux

package firewall

import (
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestOverlappingCIDRExemptionsRetainEachDeadline(t *testing.T) {
	now := time.Now().UTC()
	items := []protocol.FirewallExemption{{IP: "8.8.8.0/24", Until: now.Add(time.Hour)}, {IP: "8.8.8.128/26", Until: now.Add(2 * time.Hour)}}
	elements, err := exemptionRangeElements(items, now, false)
	if err != nil || len(elements) != 6 {
		t.Fatalf("intervals=%+v %v", elements, err)
	}
	for _, test := range []struct {
		index    int
		last     byte
		duration time.Duration
	}{{0, 0, time.Hour}, {2, 128, 2 * time.Hour}, {4, 192, time.Hour}} {
		if got := elements[test.index]; got.Key[3] != test.last || got.Timeout != test.duration {
			t.Fatal("deadline was broadened", got)
		}
	}
}
