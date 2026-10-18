package agent

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestBulkUtilitiesCannotOccupyUrgentControlSlot(t *testing.T) {
	finished := make(chan struct{}, 3)
	j, err := NewJobs(t.TempDir(), func(m protocol.Message, _ bool) bool {
		if m.Type == "command.result" {
			finished <- struct{}{}
		}
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		for range 3 {
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Error("utility did not finish")
			}
		}
	}()
	block := func(ctx context.Context, _ func(any)) (any, error) { <-ctx.Done(); return nil, ctx.Err() }
	for _, id := range []string{"one", "two"} {
		if err = j.Start(ctx, id, "geodata.refresh", block); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Start(ctx, "one", "update.install", block); err == nil {
		t.Fatal("running request ID was reused for another command")
	}
	for _, result := range j.Snapshot() {
		if result.Status == "running" && result.Command != "geodata.refresh" {
			t.Fatal("running command lost its identity", result)
		}
	}
	if err = j.Start(ctx, "overflow", "geodata.refresh", block); err == nil {
		t.Fatal("ordinary job consumed reserved capacity")
	}
	done := make(chan struct{})
	if err = j.StartControl(ctx, "ban", "firewall.bans.update", func(context.Context, func(any)) (any, error) { close(done); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ban waited for bulk utilities")
	}
}
