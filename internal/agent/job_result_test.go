package agent

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestFailedResultJournalRemainsUncertainOnReplay(t *testing.T) {
	results := make(chan protocol.Message, 2)
	jobs, err := NewJobs(t.TempDir(), func(message protocol.Message, _ bool) bool {
		if message.Type == "command.result" {
			results <- message
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	write := jobs.write
	jobs.write = func(path string, data []byte, mode os.FileMode) error {
		writes++
		if writes > 1 {
			return errors.New("synthetic result persistence failure")
		}
		return write(path, data, mode)
	}
	calls := 0
	mutate := func(context.Context, func(any)) (any, error) { calls++; return map[string]bool{"applied": true}, nil }
	if err := jobs.Start(context.Background(), "mutation", "runtime.reload", mutate); err != nil {
		t.Fatal(err)
	}
	read := func() {
		t.Helper()
		select {
		case frame := <-results:
			var result JobResult
			if err := protocol.Decode(frame.Data, &result); err != nil || result.Status != "uncertain" {
				t.Fatal("mutation certainty lost", result, err)
			}
		case <-time.After(time.Second):
			t.Fatal("result timed out")
		}
	}
	read()
	if err := jobs.Start(context.Background(), "mutation", "runtime.reload", mutate); err != nil {
		t.Fatal(err)
	}
	read()
	if calls != 1 {
		t.Fatal("ambiguous mutation repeated", calls)
	}
}
