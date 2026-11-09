package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestCertificateUncertainReplayKeepsPublicFactsWithoutReissuing(t *testing.T) {
	dir := t.TempDir()
	jobs, results := executionJobs(t, dir)
	var calls atomic.Int32
	mutate := func(context.Context, func(any)) (any, error) {
		calls.Add(1)
		return map[string]any{"profile_id": "tls", "action": "renew", "fingerprint": strings.Repeat("a", 64), "applied": true, "ready": true, "private_key": "must-not-persist"}, errors.New("activation acceptance uncertain")
	}
	if err := jobs.Start(context.Background(), "certificate-operation", protocol.CertificateRunCommand, mutate); err != nil {
		t.Fatal(err)
	}
	first := executionResult(t, results)
	raw, _ := json.Marshal(first.Data)
	if first.Status != "uncertain" || !strings.Contains(string(raw), strings.Repeat("a", 64)) || strings.Contains(string(raw), "must-not-persist") {
		t.Fatal("public partial outcome or privacy lost", first, string(raw))
	}
	restarted, replayed := executionJobs(t, dir)
	if err := restarted.Start(context.Background(), "certificate-operation", protocol.CertificateRunCommand, mutate); err != nil {
		t.Fatal(err)
	}
	if got := executionResult(t, replayed); got.Status != "uncertain" || calls.Load() != 1 {
		t.Fatal("uncertain certificate command executed again", got, calls.Load())
	}
}

func TestCertificateCommandReplayPrecedesCurrentDesiredStateGuards(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	if err := jobs.Start(context.Background(), "done", protocol.CertificateRunCommand, func(context.Context, func(any)) (any, error) {
		return protocol.CertificateRunResult{ProfileID: "tls", Action: "issue", Applied: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = executionResult(t, results)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{Jobs: jobs, Store: store} // Current desired profile no longer exists.
	message := protocol.New("command", "done", 0, map[string]any{"name": protocol.CertificateRunCommand, "args": protocol.CertificateRunArgs{ProfileID: "tls", Action: "issue", ExpectedRevision: 7}})
	if err = a.command(context.Background(), message); err != nil {
		t.Fatal("terminal replay rejected by current eligibility", err)
	}
	if got := executionResult(t, results); got.Status != "completed" {
		t.Fatal("completed receipt changed", got)
	}
}
