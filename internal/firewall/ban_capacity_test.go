package firewall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type failingBanKernel struct {
	*guardKernel
	err   error
	calls int
}

func (k *failingBanKernel) Bans(ctx context.Context, b []protocol.FirewallBan, e []protocol.FirewallExemption, s []protocol.FirewallSource, replace bool) error {
	k.calls++
	if k.err != nil {
		return k.err
	}
	return k.guardKernel.Bans(ctx, b, e, s, replace)
}

func TestEnforcementFailureBackoffAndExplicitRetry(t *testing.T) {
	g, kernel := guardFixture(t)
	k := &failingBanKernel{guardKernel: kernel, err: errors.New("persistent kernel rejection")}
	g.manager.Backend = k
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range 10 {
		if err := g.enforce(context.Background()); err == nil {
			t.Fatal("failure lost")
		}
		want := min(time.Minute, time.Second*time.Duration(1<<i))
		if g.enforceRetryDelay != want || g.enforcementDue(g.enforceRetryAt.Add(-time.Nanosecond)) || !g.enforcementDue(g.enforceRetryAt) {
			t.Fatal("incorrect retry deadline", i)
		}
	}
	if k.calls != 10 {
		t.Fatal("explicit retry was delayed")
	}
	k.err = nil
	if err := g.enforce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !g.enforceRetryAt.IsZero() || g.enforceRetryDelay != 0 {
		t.Fatal("success retained backoff")
	}
}

func TestBanCapacityPrefersMasterAndLaterDeadlines(t *testing.T) {
	now := time.Now()
	bans := []protocol.FirewallBan{
		{Prefix: "source", Source: "feed", Until: now.Add(time.Hour)},
		{Prefix: "soon", Until: now}, {Prefix: "later", Until: now.Add(time.Minute)},
	}
	got, dropped := boundedBans(bans, 1)
	if dropped != 2 || len(got) != 1 || got[0].Prefix != "later" {
		t.Fatal(got, dropped)
	}
}

func TestSourceRefreshCapAndNonBlacklistBypass(t *testing.T) {
	g, _ := guardFixture(t)
	now := time.Now()
	g.state.Sources["missing"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "missing", Generation: "one", Until: now.Add(time.Hour)}}
	processHits(t, g, "8.8.8.8", "xray_invalid", 1, now)
	if g.lookups != nil || g.kernelError != "" {
		t.Fatal("non-blacklist hit opened a source file")
	}
	ban := protocol.FirewallBan{Prefix: "8.8.8.8/32", Source: "feed", Generation: "one", Until: now.Add(time.Minute), RefreshSeconds: 3600}
	if err := g.appendJournal(journalRecord{Bans: []protocol.FirewallBan{ban}}); err != nil {
		t.Fatal(err)
	}
	g.sourceBanCount = sourceBanLimit
	processHits(t, g, "8.8.8.8", "blacklist", 1, now)
	if !g.state.Bans[ban.Prefix].Until.Equal(ban.Until) {
		t.Fatal("agent extended a master deadline")
	}
	// A second source IP is contained, but cannot allocate another local ban.
	g.mu.Lock()
	g.lookups = []sourceLookup{{id: "feed", ranges: []diskRange{}}}
	r, err := prefixRecord("8.8.4.0/24")
	if err != nil {
		t.Fatal(err)
	}
	g.lookups[0].ranges = []diskRange{r}
	g.lookupRevision = g.state.SourceRevision
	g.state.Sources["feed"] = sourceState{FirewallSource: protocol.FirewallSource{ID: "feed", Generation: "one", Until: now.Add(time.Hour), RefreshSeconds: 7200}}
	g.mu.Unlock()
	before := g.dropped.Load()
	processHits(t, g, "8.8.4.4", "source_match", 1, now)
	if _, ok := g.state.Bans["8.8.4.4/32"]; ok || g.dropped.Load() != before {
		t.Fatal("source observation allocated a local ban")
	}
}
