package monitor

import (
	"runtime/debug"
	"runtime/metrics"
)

type runtimeSample struct {
	heap [1]metrics.Sample
	gc   debug.GCStats
}

func (s *runtimeSample) collect(out *Snapshot) {
	s.heap[0].Name = "/memory/classes/heap/objects:bytes"
	metrics.Read(s.heap[:])
	// ReadGCStats exposes the same completed-cycle count and exact total
	// pause as ReadMemStats, without forcing a process-wide stop.
	debug.ReadGCStats(&s.gc)
	out.GoHeap = s.heap[0].Value.Uint64()
	out.GCCount = uint32(s.gc.NumGC)
	out.GCPauseNanos = uint64(s.gc.PauseTotal)
}
