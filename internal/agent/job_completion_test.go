package agent

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func TestTerminalResultReleasesLaneAfterBookkeepingBeforeSuccessorAdmission(t *testing.T) {
	for _, test := range []struct {
		name, command, status string
		operationError        error
		cancelled             bool
		failedWrite           int
	}{
		{name: "repeatable", command: "ddns.run", status: "completed"},
		{name: "durable", command: "update.rollback", status: "completed"},
		{name: "uncertain mutation", command: "update.rollback", status: "uncertain", operationError: errors.New("side effect failed")},
		{name: "definite refusal", command: "update.install", status: "failed", operationError: refuseJob(errors.New("invalid version"))},
		{name: "cancelled before execution", command: "update.rollback", status: "cancelled", cancelled: true},
		{name: "intent write failure", command: "update.rollback", status: "failed", failedWrite: 1},
		{name: "completion write failure", command: "update.rollback", status: "uncertain", failedWrite: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			jobs, err := NewJobs(t.TempDir(), func(protocol.Message, bool) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			if test.failedWrite != 0 {
				writes := 0 // Journal writes are serialized by persistMu.
				jobs.write = func(path string, raw []byte, mode os.FileMode) error {
					writes++
					if writes == test.failedWrite {
						return errors.New("fixture journal write failed")
					}
					return state.AtomicWrite(path, raw, mode)
				}
			}
			results := make(chan protocol.Message, 2)
			type completionObservation struct {
				snapshot []JobResult
				err      error
			}
			observed := make(chan completionObservation, 1)
			jobs.send = func(message protocol.Message, _ bool) bool {
				if message.Type != "command.result" {
					return true
				}
				if message.ID == "first" {
					// Production Send is a bounded, nonblocking queue offer. This
					// synchronous callback models its fastest possible consumer:
					// the successor arrives before the publisher returns.
					snapshot := jobs.Snapshot()
					err := jobs.start(t.Context(), "successor", protocol.HourlyCreditAckCommand, jobs.accounting, nil, func(context.Context, func(any)) (any, error) {
						return nil, nil
					})
					observed <- completionObservation{snapshot, err}
				}
				results <- message
				return true
			}
			ctx := t.Context()
			if test.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var calls atomic.Int32
			if err := jobs.start(ctx, "first", test.command, jobs.accounting, nil, func(context.Context, func(any)) (any, error) {
				calls.Add(1)
				return nil, test.operationError
			}); err != nil {
				t.Fatal(err)
			}
			completion := executionAwait(t, observed, "synchronous successor admission")
			if completion.err != nil {
				t.Fatal("published terminal result retained its worker slot", completion.err)
			}
			if len(completion.snapshot) != 1 || completion.snapshot[0].ID != "first" || completion.snapshot[0].Status != test.status {
				t.Fatal("terminal publication preceded receipt bookkeeping", completion.snapshot)
			}
			completed := make(map[string]JobResult, 2)
			for range 2 {
				result := executionResult(t, results)
				completed[result.ID] = result
			}
			if len(completed) != 2 || completed["first"].Status != test.status || completed["successor"].Status != "completed" {
				t.Fatal("completion ordering changed terminal outcome or lost the successor", completed)
			}
			wantCalls := int32(1)
			if test.cancelled || test.failedWrite == 1 {
				wantCalls = 0
			}
			if calls.Load() != wantCalls || len(jobs.accounting) != 0 {
				t.Fatal("completion changed side-effect admission or leaked worker capacity", calls.Load(), len(jobs.accounting))
			}
		})
	}
}
