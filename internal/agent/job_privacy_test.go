package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestSessionCommandResultsRemainMemoryOnly(t *testing.T) {
	done := make(chan protocol.Message, 1)
	jobs, err := NewJobs(t.TempDir(), func(message protocol.Message, _ bool) bool {
		if message.Type == "command.result" {
			done <- message
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	err = jobs.Start(context.Background(), "read-session", "connections.list", func(context.Context, func(any)) (any, error) {
		return []map[string]string{{"source_ip": "192.0.2.99"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("command did not finish")
	}
	data, err := os.ReadFile(jobs.path)
	if err != nil || strings.Contains(string(data), "192.0.2.99") || strings.Contains(string(data), "connections.list") {
		t.Fatalf("session telemetry persisted: %v", err)
	}
	if len(jobs.Snapshot()) != 1 {
		t.Fatal("live replay history disappeared")
	}
}
