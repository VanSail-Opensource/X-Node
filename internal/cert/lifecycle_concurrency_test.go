package cert

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCertificateNetworkWaitDoesNotBlockStatusOrAnotherProfile(t *testing.T) {
	p := NewPool(t.TempDir())
	c := lifecycleConfig("one.example")
	other := lifecycleConfig("two.example")
	c.Certificates["other"] = other.Certificates["tls"]
	p.Declare(c, 1)
	certificate, key := generateSelfSignedPair(t, "one.example")
	started := make(chan string, 2)
	unblock := make(chan struct{})
	p.acquireFn = func(ctx, _ context.Context, m *Manager, _ string) error {
		started <- m.cfg.Domain
		select {
		case <-unblock:
			m.storePEM(certificate, key)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 2)
	defer func() {
		cancel()
		close(unblock)
		for range 2 {
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Error("certificate worker did not drain")
			}
		}
		p.Stop()
	}()
	for _, id := range []string{"tls", "other"} {
		go func(id string) {
			_, err := p.Acquire(ctx, ctx, c, protocol.CertificateRunArgs{ProfileID: id, Action: "issue", ExpectedRevision: 1}, id)
			finished <- err
		}(id)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("profile operations serialized behind a global network lock")
		}
	}
	read := make(chan map[string]ProfileStatus, 1)
	go func() { read <- p.Status() }()
	select {
	case status := <-read:
		if len(status) != 2 {
			t.Fatal("desired profiles missing", status)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind issuance")
	}
}

func TestCertificateSupersededWhileWaitingDoesNotStartACME(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	c := lifecycleConfig("node.example")
	p.Declare(c, 1)
	var eligible atomic.Bool
	eligible.Store(true)
	var calls atomic.Int32
	p.acquireFn = func(context.Context, context.Context, *Manager, string) error { calls.Add(1); return nil }
	p.prepareMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := p.Acquire(context.Background(), context.Background(), c, protocol.CertificateRunArgs{ProfileID: "tls", Action: "issue", ExpectedRevision: 1}, "superseded", eligible.Load)
		done <- err
	}()
	eligible.Store(false)
	p.prepareMu.Unlock()
	select {
	case err := <-done:
		if err == nil || err.Error() != "CERTIFICATE_SUPERSEDED" || calls.Load() != 0 {
			t.Fatal("obsolete queued issuance started", err, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("superseded operation did not drain")
	}
}

func TestCertificatePrepareLockWaitHonorsOperationCancellation(t *testing.T) {
	p := NewPool(t.TempDir())
	defer p.Stop()
	c := lifecycleConfig("node.example")
	p.Declare(c, 1)
	p.prepareMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.Acquire(ctx, ctx, c, protocol.CertificateRunArgs{ProfileID: "tls", Action: "issue", ExpectedRevision: 1}, "cancelled")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled operation admitted")
		}
	case <-time.After(time.Second):
		p.prepareMu.Unlock()
		t.Fatal("operation blocked past cancellation")
	}
	p.prepareMu.Unlock()
}
