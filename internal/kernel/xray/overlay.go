package xray

import wire "github.com/VanSail-Opensource/X-Node/internal/protocol"

// Overlay updates non-native policy without parsing or touching a listener.
// The authoritative actor has already committed and installed authorization.
func (r *Runtime) Overlay(c wire.Config) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.instance == nil || r.current == nil || !r.instance.IsRunning() {
		return false
	}
	next := *r.current
	source := wire.Clone(c)
	// These are resolved/materialized inputs, unlike the raw desired document.
	source.Xray = next.Source.Xray
	source.Certificates = next.Source.Certificates
	next.Source, next.Counts = source, BuildCounts{}
	r.current = &next
	r.bridge.BanNanos.Store(int64(c.BanDuration()))
	r.stats.Overlays++
	r.stats.LastMode = "overlay"
	r.stats.ListenerGapMillis = 0
	return true
}
