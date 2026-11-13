package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestDurableDefiniteRefusalsRemainTerminalAcrossReplay(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "cancelled-after-refusal"}[cancelled], func(t *testing.T) {
			jobs, results := executionJobs(t, t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			fn := func(context.Context, func(any)) (any, error) {
				calls.Add(1)
				if cancelled {
					cancel()
				}
				return nil, refuseJob(errors.New("stale certificate revision rejected before mutation"))
			}
			if err := jobs.Start(ctx, "rejected-certificate", protocol.CertificateRunCommand, fn); err != nil {
				t.Fatal(err)
			}
			if result := executionResult(t, results); result.Status != "failed" {
				t.Fatal("proven refusal became uncertain", result.Status)
			}
			jobs, results = executionJobs(t, filepath.Dir(jobs.path))
			if err := jobs.Start(context.Background(), "rejected-certificate", protocol.CertificateRunCommand, fn); err != nil {
				t.Fatal(err)
			}
			if result := executionResult(t, results); result.Status != "failed" || calls.Load() != 1 {
				t.Fatal("terminal refusal was executed again")
			}
		})
	}
}

func TestDurableStorageFailureKeepsUncertainReceipt(t *testing.T) {
	jobs, results := executionJobs(t, t.TempDir())
	if err := jobs.Start(context.Background(), "storage-uncertain", protocol.CertificateRunCommand, func(context.Context, func(any)) (any, error) {
		return nil, errors.New("certificate durability barrier failed")
	}); err != nil {
		t.Fatal(err)
	}
	if result := executionResult(t, results); result.Status != "uncertain" {
		t.Fatal("storage ambiguity became evictable", result.Status)
	}
}
