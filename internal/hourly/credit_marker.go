package hourly

import "sync/atomic"

// A marker is process-local authority to activate one durable installation.
// It is never reconstructed from the journal after a restart.
type creditInstallMarker struct {
	store   *CreditStore
	valid   atomic.Bool
	claimed atomic.Bool
}

func newCreditMarker(store *CreditStore) *creditInstallMarker {
	marker := &creditInstallMarker{store: store}
	marker.valid.Store(true)
	return marker
}

func (m *creditInstallMarker) claim() bool {
	return m != nil && m.store.Healthy() && m.valid.Load() && m.claimed.CompareAndSwap(false, true) && m.valid.Load() && m.store.Healthy()
}

func (m *creditInstallMarker) active() bool {
	return m != nil && m.store.Healthy() && m.valid.Load() && m.claimed.Load()
}

func (m *creditInstallMarker) invalidate() {
	if m != nil {
		m.valid.Store(false)
	}
}
