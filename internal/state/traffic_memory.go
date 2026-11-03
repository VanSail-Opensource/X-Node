package state

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const MaxTrafficEntries = 8192
const MaxTrafficQueuedReports = 64
const MaxTrafficQueuedBytes = 32 << 20

var ErrTrafficBusy = errors.New("volatile traffic queue is full; retry the barrier")

type memoryTraffic struct {
	stream      string
	sequence    uint64
	totals      Traffic
	samples     map[string]protocol.TrafficSample
	queue       []*Batch
	queuedBytes int
	dropped     uint64
}

func (s *Store) openTraffic() error {
	// Seal only previously persisted accumulation, using its original agent and
	// sequence. Config/credential writes can never serialize the new buffer.
	if len(s.data.Accumulated)+len(s.data.Accounting) > 0 {
		next := protocol.Clone(s.data)
		if err := sealLegacyTraffic(&next); err != nil {
			return err
		}
		if err := s.persist(next); err != nil {
			return err
		}
		s.data = next
	}
	s.traffic = memoryTraffic{stream: ID(), totals: Traffic{}, samples: map[string]protocol.TrafficSample{}}
	return nil
}

func (s *Store) StreamID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.traffic.stream
}

func (m *memoryTraffic) drop(count uint64) { m.dropped += min(count, ^uint64(0)-m.dropped) }

func trafficFootprint(batch *Batch) int {
	// Conservative retained allocation allowance, including map buckets, slice
	// capacity, period strings and bookkeeping. Wire payload limits still apply.
	return 256 + len(batch.Traffic)*128 + len(batch.Samples)*640
}

func (m *memoryTraffic) seal(agent string) error {
	if len(m.totals)+len(m.samples) == 0 && m.dropped == 0 {
		return nil
	}
	size := 256 + len(m.totals)*128 + len(m.samples)*640
	if len(m.queue) >= MaxTrafficQueuedReports || size > MaxTrafficQueuedBytes-m.queuedBytes {
		return ErrTrafficBusy
	}
	if m.sequence == ^uint64(0)>>1 {
		return errors.New("traffic sequence exhausted")
	}
	m.sequence++
	batch := &Batch{ID: fmt.Sprintf("%s:%s:%d", agent, m.stream, m.sequence), StreamID: m.stream,
		Traffic: m.totals, DroppedSamples: m.dropped}
	keys := make([]string, 0, len(m.samples))
	for key := range m.samples {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	batch.Samples = make([]protocol.TrafficSample, 0, len(keys))
	for _, key := range keys {
		batch.Samples = append(batch.Samples, m.samples[key])
	}
	m.queue = append(m.queue, batch)
	m.queuedBytes += size
	m.totals, m.samples, m.dropped = Traffic{}, map[string]protocol.TrafficSample{}, 0
	return nil
}

func cloneTrafficBatch(batch *Batch) *Batch {
	if batch == nil {
		return nil
	}
	clone := *batch
	clone.Traffic, clone.Samples = maps.Clone(batch.Traffic), slices.Clone(batch.Samples)
	return &clone
}
