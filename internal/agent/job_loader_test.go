package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func journalResult(t *testing.T, results <-chan protocol.Message) JobResult {
	t.Helper()
	select {
	case message := <-results:
		var result JobResult
		if err := protocol.Decode(message.Data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("job result timed out")
		return JobResult{}
	}
}

func journalSink(results chan<- protocol.Message) func(protocol.Message, bool) bool {
	return func(message protocol.Message, _ bool) bool {
		if message.Type == "command.result" {
			results <- message
		}
		return true
	}
}

func largeLegacyJournal(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal([]JobResult{
		{ID: "large-read", Command: "firewall.status", Status: "completed", Data: strings.Repeat("x", maxJobJournalBytes)},
		{ID: "old-mutation", Command: "runtime.reload", Status: "completed", Data: map[string]bool{"applied": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestOversizedLegacyJournalPreservesEvidenceAndUncertainty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw := largeLegacyJournal(t)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	results := make(chan protocol.Message, 2)
	jobs, err := NewJobs(dir, journalSink(results))
	if err != nil || jobs.recovery != "" {
		t.Fatalf("recovery failed: %v %s", err, jobs.recovery)
	}
	compacted, err := os.ReadFile(path)
	if err != nil || len(compacted) >= maxJobJournalBytes || strings.Contains(string(compacted), "large-read") {
		t.Fatal("legacy read was not removed from bounded journal")
	}
	digest := sha256.Sum256(raw)
	evidence := path + ".legacy-" + hex.EncodeToString(digest[:])
	preserved, err := os.ReadFile(evidence)
	if err != nil || !bytes.Equal(preserved, raw) {
		t.Fatal("original evidence changed")
	}
	if info, err := os.Stat(evidence); err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("evidence is not private")
	}
	for i := 0; i < 2; i++ {
		jobs, err = NewJobs(dir, journalSink(results))
		if err != nil || jobs.recovery != "" {
			t.Fatal("compacted journal did not restart")
		}
		if err := jobs.Start(context.Background(), "old-mutation", "runtime.reload", func(context.Context, func(any)) (any, error) { t.Error("uncertain mutation replayed"); return nil, nil }); err != nil {
			t.Fatal(err)
		}
		if result := journalResult(t, results); result.Status != "uncertain" {
			t.Fatal("recovered mutation became completed")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing, err := NewJobs(dir, journalSink(results))
	if err != nil || !strings.HasPrefix(missing.recovery, "JOURNAL_PRIMARY_MISSING") {
		t.Fatal("missing primary forgot historical evidence")
	}
}

func TestUnverifiableJournalAllowsReadsButFencesDurableMutations(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`[{"id":"lost","command":"runtime.reload","status":"running"}`), bytes.Repeat([]byte(" "), legacyJobRecoveryMaxBytes+1)} {
		dir := t.TempDir()
		path := filepath.Join(dir, "jobs.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			results := make(chan protocol.Message, 1)
			jobs, err := NewJobs(dir, journalSink(results))
			if err != nil || jobs.recovery == "" {
				t.Fatal("unknown identities did not enter recovery-only mode")
			}
			if err := jobs.Start(context.Background(), "new-mutation", "runtime.reload", func(context.Context, func(any)) (any, error) {
				t.Error("unverified mutation executed")
				return nil, nil
			}); err == nil {
				t.Fatal("durable admission was not fenced")
			}
			if err := jobs.StartControl(context.Background(), "safe-read", "firewall.status", func(context.Context, func(any)) (any, error) { return map[string]bool{"read": true}, nil }); err != nil {
				t.Fatal(err)
			}
			if result := journalResult(t, results); result.Status != "completed" {
				t.Fatal("recovery read was unavailable")
			}
			preserved, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, preserved) {
				t.Fatal("unverified history was overwritten")
			}
		}
	}
}

func TestConflictingEvidenceNeverReplacesPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw := largeLegacyJournal(t)
	digest := sha256.Sum256(raw)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".legacy-"+hex.EncodeToString(digest[:]), bytes.Repeat([]byte("z"), len(raw)), 0600); err != nil {
		t.Fatal(err)
	}
	jobs, err := NewJobs(dir, func(protocol.Message, bool) bool { return true })
	if err != nil || !strings.HasPrefix(jobs.recovery, "JOURNAL_EVIDENCE") {
		t.Fatal("conflicting evidence was trusted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("conflicting recovery erased original history")
	}
}

func TestSmallJournalRetainsExactNativeIntegers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw := []byte(`[{"id":"exact","command":"traffic.flush","status":"completed","data":{"sequence":18446744073709551615}}]`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	jobs, err := NewJobs(dir, func(protocol.Message, bool) bool { return true })
	if err != nil || jobs.recovery != "" {
		t.Fatal("small journal failed to load")
	}
	after, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(after), "18446744073709551615") {
		t.Fatal("native receipt precision changed")
	}
	copy := jobs.Snapshot()
	copy[0].Data.(json.RawMessage)[0] = 'x'
	if bytes.HasPrefix(jobs.Snapshot()[0].Data.(json.RawMessage), []byte("x")) {
		t.Fatal("caller mutated stored receipt")
	}
}
