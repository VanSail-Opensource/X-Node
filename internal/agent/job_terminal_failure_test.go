package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestTerminalFailuresRemainEvictableAfterRestart(t *testing.T) {
	dir := t.TempDir()
	jobs, _ := executionJobs(t, dir)
	for i := range maxJobHistory {
		result := boundedJobResult(JobResult{ID: fmt.Sprint(i), Command: protocol.CertificateRunCommand, Status: "failed", terminalFailure: true})
		var err error
		jobs.history, err = retainJob(jobs.history, result, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := jobs.writeHistory(jobs.history); err != nil {
		t.Fatal(err)
	}
	jobs, results := executionJobs(t, dir)
	for _, receipt := range jobs.Snapshot() {
		if receipt.Status != "failed" || !receipt.terminalFailure {
			t.Fatal("proven terminal failure became a protected obligation")
		}
	}
	if err := jobs.Start(context.Background(), "fresh", "update.rollback", func(context.Context, func(any)) (any, error) {
		return map[string]bool{"applied": true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, results); result.Status != "completed" {
		t.Fatal("terminal refusal history fenced unrelated recovery", result)
	}
}

func TestTerminalFailureMarkerNeverEntersCommandWire(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	if err := jobs.Start(context.Background(), "refused", protocol.CertificateRunCommand, func(context.Context, func(any)) (any, error) {
		return nil, refuseJob(errors.New("stale session"))
	}); err != nil {
		t.Fatal(err)
	}
	message := executionAwait(t, results, "terminal refusal")
	var legacyResult struct {
		ID, Command, Status, Error string
		Data                       json.RawMessage
		Finished                   json.RawMessage
	}
	if err := protocol.Decode(message.Data, &legacyResult); err != nil || legacyResult.Status != "failed" {
		t.Fatal("private journal evidence changed the strict public result shape", err)
	}
	jobs.mu.Lock()
	receipt := jobs.history[0]
	jobs.mu.Unlock()
	if !receipt.terminalFailure {
		t.Fatal("terminal refusal lost its persisted classification")
	}
	raw, err := marshalJobBounded(journalJobResult{JobResult: receipt, TerminalFailure: true}, maxJobResultBytes)
	if err != nil || len(raw) != receipt.encodedBytes {
		t.Fatal("journal capacity omitted private evidence bytes", len(raw), receipt.encodedBytes, err)
	}
}

func TestFailedTerminalReceiptPersistenceStillReplaysUncertain(t *testing.T) {
	dir := t.TempDir()
	jobs, results := executionJobs(t, dir)
	write := jobs.write
	writes := 0
	jobs.write = func(path string, raw []byte, mode os.FileMode) error {
		writes++
		if writes == 2 {
			return errors.New("constructed terminal receipt durability failure")
		}
		return write(path, raw, mode)
	}
	if err := jobs.Start(context.Background(), "refused", protocol.CertificateRunCommand, func(context.Context, func(any)) (any, error) {
		return nil, refuseJob(errors.New("stale session"))
	}); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, results); result.Status != "uncertain" {
		t.Fatal("failed persistence exposed an evictable terminal result")
	}
	jobs, results = executionJobs(t, dir)
	if err := jobs.Start(context.Background(), "refused", protocol.CertificateRunCommand, func(context.Context, func(any)) (any, error) {
		t.Error("unproved terminal result executed again")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, results); result.Status != "uncertain" {
		t.Fatal("restart discarded an uncommitted terminal receipt")
	}
}

func TestTerminalFailureMarkerSharesPerReceiptByteLimit(t *testing.T) {
	const limit = 512
	result := JobResult{ID: "boundary", Command: "update.rollback", Status: "failed", Data: "", terminalFailure: true}
	base, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	// The public shape fits exactly; its private proof marker must also fit
	// before this receipt can be retained as a terminal result.
	result.Data = strings.Repeat("x", limit-len(base))
	bounded := limitJobResult(result, limit)
	raw, err := marshalJobBounded(journalJobResult{JobResult: bounded, TerminalFailure: bounded.terminalFailure}, limit)
	if err != nil || len(raw) != bounded.encodedBytes || len(raw) > limit {
		t.Fatal("private proof marker exceeded the per-receipt byte bound", err, len(raw), bounded.encodedBytes)
	}
	if bounded.Status != "uncertain" || bounded.terminalFailure {
		t.Fatal("oversized persistent receipt did not retain its conservative fallback")
	}
}
