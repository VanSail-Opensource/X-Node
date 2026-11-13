package agent

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func executionAwait[T any](t *testing.T, channel <-chan T, operation string) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
	var zero T
	return zero
}

func executionJobs(t *testing.T, dir string) (*Jobs, <-chan protocol.Message) {
	t.Helper()
	results := make(chan protocol.Message, 32)
	jobs, err := NewJobs(dir, func(message protocol.Message, _ bool) bool {
		if message.Type == "command.result" {
			results <- message
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if jobs == nil || jobs.recovery != "" {
		t.Fatal("command executor unexpectedly requires recovery")
	}
	return jobs, results
}

func executionResult(t *testing.T, results <-chan protocol.Message) JobResult {
	t.Helper()
	message := executionAwait(t, results, "command result")
	var result JobResult
	if err := protocol.Decode(message.Data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func executionStart(t *testing.T, start func() error) error {
	t.Helper()
	returned := make(chan error, 1)
	go func() { returned <- start() }()
	return executionAwait(t, returned, "nonblocking command admission")
}

func executionGate() (chan struct{}, func()) {
	gate := make(chan struct{})
	var once sync.Once
	return gate, func() { once.Do(func() { close(gate) }) }
}

func TestBlockedJournalWritesDoNotBlockAdmissionOrInspection(t *testing.T) {
	for _, test := range []struct {
		name  string
		write int
	}{{"intent", 1}, {"completion", 2}} {
		t.Run(test.name, func(t *testing.T) {
			jobs, results := executionJobs(t, t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			gate, unblock := executionGate()
			defer func() { cancel(); unblock() }()
			blocked := make(chan struct{})
			writes := 0 // Executor serializes this hook with persistMu.
			jobs.write = func(path string, raw []byte, mode os.FileMode) error {
				writes++
				if writes == test.write {
					close(blocked)
					<-gate
				}
				return state.AtomicWrite(path, raw, mode)
			}
			var firstCalls, secondCalls, controlCalls atomic.Int32
			first := func(context.Context, func(any)) (any, error) { firstCalls.Add(1); return nil, nil }
			if err := executionStart(t, func() error { return jobs.Start(ctx, "first", "update.rollback", first) }); err != nil {
				t.Fatal(err)
			}
			executionAwait(t, blocked, "blocked journal write")
			if firstCalls.Load() != int32(test.write-1) {
				t.Fatal("mutation crossed an uncommitted intent barrier")
			}
			snapshot := make(chan []JobResult, 1)
			go func() { snapshot <- jobs.Snapshot() }()
			seen := executionAwait(t, snapshot, "journal-independent inspection")
			if len(seen) != 1 || seen[0].ID != "first" || seen[0].Status != "running" {
				t.Fatal("blocked command lost its running identity", seen)
			}
			if err := executionStart(t, func() error { return jobs.Start(ctx, "first", "update.rollback", first) }); err != nil {
				t.Fatal("same-command retry blocked behind disk", err)
			}
			if err := executionStart(t, func() error { return jobs.Start(ctx, "first", "update.install", first) }); err == nil {
				t.Fatal("running request identity accepted another command")
			}
			if err := executionStart(t, func() error {
				return jobs.Start(ctx, "second", "firewall.apply", func(context.Context, func(any)) (any, error) {
					secondCalls.Add(1)
					return nil, nil
				})
			}); err != nil {
				t.Fatal("another admission blocked behind disk", err)
			}
			if err := executionStart(t, func() error {
				return jobs.StartControl(ctx, "observe", "firewall.status", func(context.Context, func(any)) (any, error) {
					controlCalls.Add(1)
					return map[string]bool{"observed": true}, nil
				})
			}); err != nil {
				t.Fatal("read-only control blocked behind disk", err)
			}
			observed := executionResult(t, results)
			if observed.ID != "observe" || observed.Status != "completed" || controlCalls.Load() != 1 {
				t.Fatal("read-only control did not finish before disk was released", observed)
			}
			if secondCalls.Load() != 0 {
				t.Fatal("queued mutation crossed its uncommitted intent barrier")
			}
			unblock()
			completed := map[string]bool{}
			for range 2 {
				result := executionResult(t, results)
				if result.Status != "completed" || result.ID != "first" && result.ID != "second" {
					t.Fatal("unexpected durable completion", result)
				}
				completed[result.ID] = true
			}
			if len(completed) != 2 || firstCalls.Load() != 1 || secondCalls.Load() != 1 {
				t.Fatal("blocked persistence repeated or lost a mutation")
			}
		})
	}
}
