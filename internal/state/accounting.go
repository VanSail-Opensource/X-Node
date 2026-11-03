package state

import (
	"errors"
	"fmt"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// AddAccounting changes only bounded volatile storage. Validate the complete
// capture before mutation; overflow cannot partially change accepted counters.
func (s *Store) AddAccounting(delta Traffic, samples []protocol.TrafficSample) error {
	if len(delta)+len(samples) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := &s.traffic
	if len(delta) > MaxTrafficEntries || len(samples) > MaxTrafficEntries {
		m.drop(uint64(max(1, len(samples))))
		return nil
	}
	totals := make(Traffic, len(delta))
	for id, value := range delta {
		old := m.totals[id]
		if id <= 0 || ^uint64(0)-old[0] < value[0] || ^uint64(0)-old[1] < value[1] {
			return errors.New("invalid or overflowing traffic counter")
		}
		totals[id] = [2]uint64{old[0] + value[0], old[1] + value[1]}
	}
	updates := make(map[string]protocol.TrafficSample, len(samples))
	for _, sample := range samples {
		if sample.UserID <= 0 || !protocol.ValidName(sample.AccountingPeriod) || len(sample.AccountingPeriod) > 128 || sample.From.IsZero() || sample.Through.Before(sample.From) {
			return errors.New("invalid accounting sample")
		}
		// Never coalesce across a period, capture minute or a sample spanning a
		// different minute. A rate-change flush seals the entire prior batch.
		key := fmt.Sprintf("%d:%s:%d:%d", sample.UserID, sample.AccountingPeriod, sample.From.UTC().Unix()/60, sample.Through.UTC().Unix()/60)
		old, exists := updates[key]
		if !exists {
			old, exists = m.samples[key]
		}
		if !exists {
			updates[key] = sample
			continue
		}
		if ^uint64(0)-old.UploadBytes < sample.UploadBytes || ^uint64(0)-old.DownloadBytes < sample.DownloadBytes {
			return errors.New("accounting counter overflow")
		}
		old.UploadBytes += sample.UploadBytes
		old.DownloadBytes += sample.DownloadBytes
		if sample.From.Before(old.From) {
			old.From = sample.From
		}
		if sample.Through.After(old.Through) {
			old.Through = sample.Through
		}
		updates[key] = old
	}
	entries := len(m.totals) + len(m.samples)
	for id := range totals {
		if _, ok := m.totals[id]; !ok {
			entries++
		}
	}
	for key := range updates {
		if _, ok := m.samples[key]; !ok {
			entries++
		}
	}
	if entries > MaxTrafficEntries {
		m.drop(uint64(max(1, len(samples))))
		return nil
	}
	for id, value := range totals {
		m.totals[id] = value
	}
	for key, value := range updates {
		m.samples[key] = value
	}
	return nil
}

// Flush seals known usage. Queue pressure is a retryable barrier failure, never a
// durable-storage failure and never permission to pause member admission.
func (s *Store) Flush() (protocol.TrafficBarrier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.traffic.seal(s.data.AgentID)
	barrier := protocol.TrafficBarrier{AgentID: s.data.AgentID, StreamID: s.traffic.stream, Sequence: s.traffic.sequence, Through: time.Now().UTC()}
	if s.data.Pending != nil {
		barrier.LegacySequence = s.data.Sequence
	}
	return barrier, err
}
