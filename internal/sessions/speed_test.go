package sessions

import (
	"context"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"testing"
	"time"
)

func TestSustainedNormalLimitAndRecovery(t *testing.T) {
	p := newSpeedPolicy(protocol.User{SpeedLimitMbps: 1, BurstSpeedLimitMbps: 4, SpeedLimitAfterSeconds: 3, SpeedLimitResetSeconds: 2})
	now := time.Now()
	p.advance(now)
	for i := 1; i <= 3; i++ {
		p.bytes = 250000
		p.advance(now.Add(time.Duration(i) * time.Second))
		if p.limited != (i == 3) {
			t.Fatalf("incorrect transition at second %d", i)
		}
	}
	if p.status().ActiveMbps != 1 {
		t.Fatal("normal cap not applied")
	}
	p.bytes = 0
	p.advance(now.Add(4 * time.Second))
	if !p.limited {
		t.Fatal("recovery occurred too soon")
	}
	p.bytes = 0
	p.advance(now.Add(5 * time.Second))
	if p.limited || p.status().ActiveMbps != 4 {
		t.Fatal("burst did not recover")
	}
	// A below-normal interval breaks a consecutive high-traffic streak.
	p.bytes = 250000
	p.advance(now.Add(6 * time.Second))
	p.bytes = 1000
	p.advance(now.Add(7 * time.Second))
	p.bytes = 250000
	p.advance(now.Add(8 * time.Second))
	if p.limited {
		t.Fatal("nonconsecutive intervals activated normal cap")
	}
}
func TestBurstCapAlwaysAppliesAndCancellation(t *testing.T) {
	p := newSpeedPolicy(protocol.User{SpeedLimitMbps: 1, BurstSpeedLimitMbps: 2})
	started := time.Now()
	if e := p.wait(context.Background(), 125000); e != nil {
		t.Fatal(e)
	}
	if time.Since(started) < 350*time.Millisecond {
		t.Fatal("burst cap was bypassed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := p.wait(ctx, 1<<20); e == nil {
		t.Fatal("cancelled transfer admitted")
	}
}
