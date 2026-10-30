package firewall

import (
	"context"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type waitingKernel struct {
	*guardKernel
	entered chan struct{}
	release chan struct{}
}

func (k *waitingKernel) Bans(ctx context.Context, bans []protocol.FirewallBan, exemptions []protocol.FirewallExemption, sources []protocol.FirewallSource, replace bool) error {
	close(k.entered)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-k.release:
		return k.guardKernel.Bans(ctx, bans, exemptions, sources, replace)
	}
}

func TestKernelApplyReleasesGuardLockAndFencesStaleRevision(t *testing.T) {
	g, kernel := guardFixture(t)
	waiting := &waitingKernel{guardKernel: kernel, entered: make(chan struct{}), release: make(chan struct{})}
	g.manager.Backend = waiting
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		g.mu.Lock()
		err := g.enforce(ctx)
		g.mu.Unlock()
		done <- err
	}()
	select {
	case <-waiting.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("kernel application did not start")
	}
	changed := make(chan struct{})
	go func() {
		g.mu.Lock()
		g.state.Revision++
		g.dirty = true
		g.mu.Unlock()
		close(changed)
	}()
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("kernel application held the guard lock")
	}
	close(waiting.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.dirty {
		t.Fatal("stale kernel completion cleared newer work")
	}
}
