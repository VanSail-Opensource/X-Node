package state

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (s *Store) AddTraffic(delta Traffic) error { return s.AddAccounting(delta, nil) }

// Batch returns the oldest immutable unacknowledged batch.
func (s *Store) Batch() (*Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Pending != nil {
		return protocol.Clone(s.data.Pending), nil
	}
	if len(s.data.Accumulated) == 0 && len(s.data.Accounting) == 0 {
		return nil, nil
	}
	next := protocol.Clone(s.data)
	if err := sealTraffic(&next); err != nil {
		return nil, err
	}
	if err := s.persist(next); err != nil {
		return nil, err
	}
	s.data = next
	return protocol.Clone(next.Pending), nil
}

// Ack retires only the matching head and advances queued barrier batches in order.
func (s *Store) Ack(id string) error {
	_, err := s.Acknowledge(id)
	return err
}

// Acknowledge reports durable progress. Duplicate/stale ACKs do not write disk.
func (s *Store) Acknowledge(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Pending == nil || s.data.Pending.ID != id {
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

// Pending returns only the sealed head; it never seals newly accumulated bytes.
func (s *Store) Pending() *Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return protocol.Clone(s.data.Pending)
}
