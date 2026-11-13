package agent

import (
	"context"
	"sync"
)

// utilityLock bounds waiting by the operation's lifetime. A superseded or
// cancelled job must release its executor even while another job still owns
// a shared native/provider resource. The zero value is ready for use.
type utilityLock struct {
	once sync.Once
	gate chan struct{}
}

func (m *utilityLock) LockContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.once.Do(func() { m.gate = make(chan struct{}, 1) })
	select {
	case m.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *utilityLock) Unlock() {
	select {
	case <-m.gate:
	default:
		panic("unlock of unlocked utility lock")
	}
}
