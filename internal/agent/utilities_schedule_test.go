package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestScheduledDDNSJobsHaveDistinctReceiptsAndRetryBusyAdmission(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	now := time.Now()
	jobs, results := executionJobs(t, t.TempDir())
	a := &Agent{Jobs: jobs, lastDDNS: map[string]time.Time{}, lastUpdate: now}
	for _, id := range []string{"first", "second", strings.Repeat("j", 128)} {
		a.desired.DDNS = append(a.desired.DDNS, protocol.DDNSJob{ID: id, Provider: protocol.BuiltinDDNSProvider, IPv4: "192.0.2.1"})
	}
	// Hold provider execution so the third due job must encounter both slots busy.
	if err := a.dnsMu.LockContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.scheduleUtilities(context.Background(), now)
	if len(a.lastDDNS) != 2 {
		a.dnsMu.Unlock()
		t.Fatal("duplicate job IDs or rejected admission consumed a refresh interval", len(a.lastDDNS))
	}
	a.dnsMu.Unlock()
	seen := map[string]bool{}
	for range 2 {
		result := executionResult(t, results)
		var discovery dns.Result
		raw, err := json.Marshal(result.Data)
		if err != nil || protocol.Decode(raw, &discovery) != nil || result.Status != "completed" || seen[discovery.ID] {
			t.Fatal("distinct scheduled DDNS jobs did not execute", result)
		}
		seen[discovery.ID] = true
	}
	awaitUtilitySlots(t, jobs)
	a.scheduleUtilities(context.Background(), now.Add(time.Second))
	result := executionResult(t, results)
	var discovery dns.Result
	raw, err := json.Marshal(result.Data)
	if err != nil || protocol.Decode(raw, &discovery) != nil || result.Status != "completed" || seen[discovery.ID] || len(a.lastDDNS) != 3 {
		t.Fatal("busy DDNS job waited for a refresh interval or exceeded request identity bounds", result)
	}
}

func TestBusyUtilitiesDoNotPostponeDailyUpdateCheck(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	jobs, results := executionJobs(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, id := range []string{"one", "two"} {
		if err := jobs.Start(ctx, id, "firewall.status", func(ctx context.Context, _ func(any)) (any, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{Jobs: jobs, lastDDNS: map[string]time.Time{}}
	a.scheduleUtilities(ctx, time.Now())
	if !a.lastUpdate.IsZero() {
		t.Fatal("a rejected update check was postponed for a day")
	}
	cancel()
	for range 2 {
		executionResult(t, results)
	}
}

func awaitUtilitySlots(t *testing.T, jobs *Jobs) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for len(jobs.slots) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("completed utility slots did not drain")
		}
		time.Sleep(time.Millisecond)
	}
}
