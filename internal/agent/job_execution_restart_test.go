package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestIntentWriteFailurePreventsExecution(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	var calls, writes atomic.Int32
	jobs.write = func(string, []byte, os.FileMode) error {
		writes.Add(1)
		return errors.New("constructed intent write failure")
	}
	mutate := func(context.Context, func(any)) (any, error) { calls.Add(1); return nil, nil }
	for range 2 {
		if err := jobs.Start(context.Background(), "not-executed", "runtime.reload", mutate); err != nil {
			t.Fatal(err)
		}
		if result := executionResult(t, results); result.Status != "failed" {
			t.Fatal("failed admission was presented as a mutation outcome", result)
		}
	}
	if calls.Load() != 0 || writes.Load() != 1 {
		t.Fatal("an uncommitted intent executed or replay retried the write")
	}
	if _, err := os.Stat(jobs.path); !os.IsNotExist(err) {
		t.Fatalf("failed intent left unexpected durable state: %v", err)
	}
}

func TestCompletionWriteFailureRetainsUncertainIntentAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	jobs, results := executionJobs(t, dir)
	writes := 0 // Serial executor journal hook; result receipt synchronizes reads.
	jobs.write = func(path string, raw []byte, mode os.FileMode) error {
		writes++
		if writes > 1 {
			return errors.New("constructed completion write failure")
		}
		return state.AtomicWrite(path, raw, mode)
	}
	var calls atomic.Int32
	mutate := func(context.Context, func(any)) (any, error) {
		calls.Add(1)
		return map[string]bool{"applied": true}, nil
	}
	if err := jobs.Start(context.Background(), "mutated", "runtime.reload", mutate); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, results); result.Status != "uncertain" || writes != 2 || calls.Load() != 1 {
		t.Fatal("ambiguous completion lost its execution evidence", result)
	}
	raw, err := os.ReadFile(jobs.path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted []JobResult
	if err := json.Unmarshal(raw, &persisted); err != nil || len(persisted) != 1 || persisted[0].ID != "mutated" || persisted[0].Command != "runtime.reload" || persisted[0].Status != "uncertain" {
		t.Fatalf("pre-execution intent did not survive failed completion: %v", err)
	}
	restarted, replay := executionJobs(t, dir)
	for range 2 {
		if err := restarted.Start(context.Background(), "mutated", "runtime.reload", mutate); err != nil {
			t.Fatal(err)
		}
		if result := executionResult(t, replay); result.Status != "uncertain" || result.ID != "mutated" {
			t.Fatal("restart converted uncertainty into a fresh operation", result)
		}
	}
	if err := restarted.Start(context.Background(), "mutated", "update.install", mutate); err == nil {
		t.Fatal("uncertain receipt accepted another command after restart")
	}
	if calls.Load() != 1 {
		t.Fatal("a mutation with an uncertain durable receipt executed again")
	}
}

func TestCancellationBeforeMutationPreventsExecution(t *testing.T) {
	for _, blockedIntent := range []bool{false, true} {
		name := "before admission"
		if blockedIntent {
			name = "during intent write"
		}
		t.Run(name, func(t *testing.T) {
			jobs, results := executionJobs(t, t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			gate, unblock := executionGate()
			defer func() { cancel(); unblock() }()
			entered := make(chan struct{})
			writes := 0
			jobs.write = func(path string, raw []byte, mode os.FileMode) error {
				writes++
				if writes == 1 && blockedIntent {
					close(entered)
					<-gate
				}
				return state.AtomicWrite(path, raw, mode)
			}
			var calls atomic.Int32
			if !blockedIntent {
				cancel()
			}
			if err := jobs.Start(ctx, "cancelled-before-effect", "runtime.reload", func(context.Context, func(any)) (any, error) { calls.Add(1); return nil, nil }); err != nil {
				t.Fatal(err)
			}
			if blockedIntent {
				executionAwait(t, entered, "intent write before cancellation")
				cancel()
				unblock()
			}
			result := executionResult(t, results)
			if calls.Load() != 0 || result.Status != "cancelled" && result.Status != "failed" {
				t.Fatal("cancelled admission executed or became successful", result)
			}
			if !blockedIntent && writes != 0 {
				t.Fatal("already-cancelled admission wrote a mutation intent")
			}
			if blockedIntent {
				restarted, err := NewJobs(filepath.Dir(jobs.path), jobs.send)
				if err != nil || restarted.recovery != "" {
					t.Fatal("cancelled intent did not restart safely", err)
				}
				if receipts := restarted.Snapshot(); len(receipts) != 1 || receipts[0].Status != "failed" || !receipts[0].terminalFailure {
					t.Fatal("cancellation before execution became an uncertain mutation", receipts)
				}
			}
		})
	}
}

func TestInterruptedMutationIntentReplaysWithoutExecuting(t *testing.T) {
	dir := t.TempDir()
	jobs, results := executionJobs(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	gate, unblock := executionGate()
	defer func() { cancel(); unblock() }()
	entered := make(chan struct{})
	var calls atomic.Int32
	if err := jobs.Start(ctx, "interrupted", "runtime.reload", func(context.Context, func(any)) (any, error) {
		calls.Add(1)
		close(entered)
		<-gate
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	executionAwait(t, entered, "mutation after persisted intent")
	restarted, replay := executionJobs(t, dir)
	if err := restarted.Start(context.Background(), "interrupted", "runtime.reload", func(context.Context, func(any)) (any, error) { calls.Add(100); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, replay); result.Status != "uncertain" || result.ID != "interrupted" || calls.Load() != 1 {
		t.Fatal("interrupted intent was not replayed conservatively", result)
	}
	cancel()
	unblock()
	if result := executionResult(t, results); result.Status != "uncertain" {
		t.Fatal("cancelled in-flight mutation lost its uncertain outcome", result)
	}
}
