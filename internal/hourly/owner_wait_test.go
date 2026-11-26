package hourly

import (
	"testing"
	"time"
)

func TestOwnerWaitChannelRearmsAfterGrantChange(t *testing.T) {
	f := newAdmissionFixture(t)
	owner := f.flow.owner
	if owner.changed != nil {
		t.Fatal("owner allocated a channel without a waiter")
	}
	waitUntilChange := func() <-chan struct{} {
		t.Helper()
		permit, wait, err := f.flow.TryAcquire(Download, 128, 1)
		if err != nil || permit != nil || wait.Changed == nil {
			t.Fatalf("expected blocked acquire with wake signal, permit=%v wait=%+v err=%v", permit, wait, err)
		}
		return wait.Changed
	}
	first := waitUntilChange()
	if second := waitUntilChange(); second != first {
		t.Fatal("waiters on the same owner change should share a channel")
	}
	f.grant(t, 1, 0, 0)
	select {
	case <-first:
	default:
		t.Fatal("applying a grant should wake the previous generation")
	}
	second := waitUntilChange()
	if first == second {
		t.Fatal("next waiter must not reuse a closed channel")
	}
	select {
	case <-second:
		t.Fatal("next generation was already closed")
	default:
	}
	f.flow.Close()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("flow closure did not wake the waiter")
	}
}
