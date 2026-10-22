package agent

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestReloadWaitsForActivationAndPropagatesFailure(t *testing.T) {
	a := &Agent{notify: make(chan reloadRequest, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := a.reloadRuntime(ctx, "reload"); finished <- err }()
	request := <-a.notify
	if request.Force || request.RefreshAssets {
		t.Fatal("ordinary reload requested forced recovery")
	}
	select {
	case <-finished:
		t.Fatal("queued reload was reported complete")
	default:
	}
	failure := errors.New("asset validation failed")
	finishReload(request.Done, failure)
	if err := <-finished; !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if request.Context.Err() == nil {
		t.Fatal("completed reload context was retained")
	}
}

func TestForcedRecoveryIsExplicit(t *testing.T) {
	a := &Agent{notify: make(chan reloadRequest, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := a.reloadRuntime(ctx, "forced", reloadOptions{Force: true}); finished <- err }()
	request := <-a.notify
	if !request.Force || request.RefreshAssets {
		t.Fatal("forced recovery option lost")
	}
	failure := errors.New("superseded")
	finishReload(request.Done, failure)
	if err := <-finished; !errors.Is(err, failure) {
		t.Fatal(err)
	}
}

func TestSupersededReloadCannotBlockActor(t *testing.T) {
	done := make(chan error, 1)
	finishReload(done, errors.New("superseded"))
	finishReload(done, errors.New("late result"))
	if err := <-done; err == nil || err.Error() != "superseded" {
		t.Fatal(err)
	}
}
