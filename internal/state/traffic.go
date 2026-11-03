package state

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (s *Store) AddTraffic(delta Traffic) error { return s.AddAccounting(delta, nil) }

// Batch drains historical journals before the current boot's immutable queue.
func (s *Store) Batch() (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Pending != nil {
		return cloneTrafficBatch(s.data.Pending), nil
	}
	if len(s.traffic.queue) == 0 {
		if err := s.traffic.seal(s.data.AgentID); err != nil {
			return nil, err
		}
	}
	return cloneTrafficBatch(s.pendingLocked()), nil
}

func (s *Store) Ack(id string) error { _, err := s.Acknowledge(id); return err }

// Only pre-upgrade journal retirement is durable. New traffic ACKs and retries
// never touch the filesystem, including while persistent configuration is saved.
func (s *Store) Acknowledge(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Pending != nil {
		if s.data.Pending.ID != id {
			return false, nil
		}
		next := protocol.Clone(s.data)
		next.Pending = nil
		if len(next.Backlog) > 0 {
			next.Pending, next.Backlog = next.Backlog[0], next.Backlog[1:]
		}
		if err := s.persist(next); err != nil {
			return false, err
		}
		s.data = next
		return true, nil
	}
	m := &s.traffic
	if len(m.queue) == 0 || m.queue[0].ID != id {
		return false, nil
	}
	m.queuedBytes -= trafficFootprint(m.queue[0])
	copy(m.queue, m.queue[1:])
	m.queue[len(m.queue)-1] = nil
	m.queue = m.queue[:len(m.queue)-1]
	return true, nil
}

func (s *Store) pendingLocked() *Batch {
	if s.data.Pending != nil {
		return s.data.Pending
	}
	if len(s.traffic.queue) > 0 {
		return s.traffic.queue[0]
	}
	return nil
}

// Pending returns only a sealed head. Ordinary sampling/reporting seals new data
// on the configured report interval, independently of acknowledgement replay.
func (s *Store) Pending() *Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneTrafficBatch(s.pendingLocked())
}
