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
	return s.change(func(d *Data) error {
		if d.Pending != nil && d.Pending.ID == id {
			d.Pending = nil
			if len(d.Backlog) > 0 {
				d.Pending = d.Backlog[0]
				d.Backlog = d.Backlog[1:]
			}
		}
		return nil
	})
}
