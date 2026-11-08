package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFailedCompactionPreservesPrimaryAndReusesPrivateEvidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw := largeLegacyJournal(t)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	broken := &Jobs{path: path, write: func(string, []byte, os.FileMode) error { return errors.New("constructed compact write failure") }}
	if err := broken.loadHistory(); err == nil || !strings.HasPrefix(err.Error(), "JOURNAL_COMPACTION") {
		t.Fatal("compaction failure was not surfaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, raw) {
		t.Fatal("failed compaction changed primary evidence")
	}
	results := make(chan protocol.Message, 1)
	jobs, err := NewJobs(dir, journalSink(results))
	if err != nil || jobs.recovery != "" {
		t.Fatal("private evidence could not be reused after a failed compaction")
	}
	if err := jobs.Start(context.Background(), "old-mutation", "runtime.reload", func(context.Context, func(any)) (any, error) { t.Error("recovered mutation repeated"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if result := journalResult(t, results); result.Status != "uncertain" {
		t.Fatal("evidence retry changed uncertainty")
	}
}

func TestMutationErrorsAfterSideEffectsRemainProtected(t *testing.T) {
	results := make(chan protocol.Message, 2)
	dir := t.TempDir()
	jobs, err := NewJobs(dir, journalSink(results))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	mutate := func(context.Context, func(any)) (any, error) {
		calls++
		return nil, errors.New("provider succeeded but durable result failed")
	}
	if err := jobs.Start(context.Background(), "partial", "ddns.run", mutate); err != nil {
		t.Fatal(err)
	}
	if result := journalResult(t, results); result.Status != "uncertain" {
		t.Fatal("an ordinary error falsely proved no side effects")
	}
	restarted, err := NewJobs(dir, journalSink(results))
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(context.Background(), "partial", "ddns.run", mutate); err != nil {
		t.Fatal(err)
	}
	if result := journalResult(t, results); result.Status != "uncertain" || calls != 1 {
		t.Fatal("partial mutation was repeated after restart")
	}
}

func TestLegacyFailedMutationIsNotTreatedAsProofOfNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs.json")
	raw := []byte(`[{"id":"legacy-failure","command":"ddns.run","status":"failed","error":"provider journal failed"}]`)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	jobs, err := NewJobs(dir, func(protocol.Message, bool) bool { return true })
	if err != nil || jobs.recovery != "" {
		t.Fatal("legacy failure could not be recovered")
	}
	if receipts := jobs.Snapshot(); len(receipts) != 1 || receipts[0].Status != "uncertain" {
		t.Fatal("old failure discarded mutation uncertainty")
	}
	backups, err := filepath.Glob(path + ".legacy-*")
	if err != nil || len(backups) != 1 {
		t.Fatal("legacy failure evidence was not retained")
	}
	preserved, err := os.ReadFile(backups[0])
	if err != nil || !bytes.Equal(preserved, raw) {
		t.Fatal("legacy failure evidence changed")
	}
}
