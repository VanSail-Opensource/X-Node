package agent

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestAutomaticLeaseJobCompletesWithNoWritableHistory(t *testing.T) {
	completed := make(chan JobResult, 1)
	jobs, err := NewJobs(t.TempDir(), func(m protocol.Message, _ bool) bool {
		if m.Type == "command.result" {
			var result JobResult
			if err := protocol.Decode(m.Data, &result); err != nil {
				t.Error(err)
			}
			completed <- result
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	jobs.path = t.TempDir() // A directory is never a writable JSON history file.
	err = jobs.StartControl(context.Background(), "lease", protocol.AutomaticLeaseCommand, func(context.Context, func(any)) (any, error) {
		return protocol.AutomaticLeaseAck{Epoch: "master", Generation: 7}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-completed:
		if result.Status != "completed" || len(durableJobHistory(jobs.Snapshot())) != 0 {
			t.Fatal("volatile grant tried to persist a command receipt", result)
		}
	case <-time.After(time.Second):
		t.Fatal("volatile command did not complete")
	}
}
