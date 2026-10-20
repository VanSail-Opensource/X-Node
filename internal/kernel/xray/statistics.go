package xray

// Statistics exposes memory-only cumulative work counters for diagnostics and
// hosted regressions. It contains no credentials, client addresses or counters
// used for billing.
type Statistics struct {
	NativeBuilds, InboundBuilds, OutboundBuilds, RoutingBuilds          uint64
	MatcherBuilds, HandlerReplacements, Rebuilds, LiveApplies, Overlays uint64
	LastMode                                                            string
	ListenerGapMillis, ListenerGapMicros                                int64
}

func (r *Runtime) Statistics() Statistics {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *Runtime) recordBuilds(p *Prepared) {
	r.stats.NativeBuilds += uint64(p.Counts.Native)
	r.stats.InboundBuilds += uint64(p.Counts.Inbounds)
	r.stats.OutboundBuilds += uint64(p.Counts.Outbounds)
	r.stats.RoutingBuilds += uint64(p.Counts.Routing)
}
