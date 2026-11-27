package state

import (
	"errors"
	"reflect"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Stage retains a validated activation target across listener failures/restarts.
// The last successfully applied Config and ConfigRevision remain unchanged.
func (s *Store) Stage(c protocol.Config, revision uint64) error {
	return s.recordConfiguration(c, revision, true)
}

func (s *Store) Accept(c protocol.Config, revision uint64) error {
	return s.recordConfiguration(c, revision, false)
}

func (s *Store) recordConfiguration(c protocol.Config, revision uint64, stage bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.data.Revision {
		return errors.New("authorization revision changed")
	}
	c.Users = s.data.Users
	if stage && reflect.DeepEqual(s.data.DesiredConfig, &c) {
		return nil
	}
	if s.data.DesiredConfig == nil && s.data.ConfigRevision == revision && reflect.DeepEqual(s.data.Config, &c) {
		return nil // accepted configuration is already durable at this revision
	}
	next := s.data // replace immutable pointers only; retain historical users
	users := c.Users
	c.Users = nil
	c = protocol.Clone(c)
	c.Users = users
	if stage {
		next.DesiredConfig = &c
	} else {
		next.Config, next.ConfigRevision, next.DesiredConfig = &c, revision, nil
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.data = next
	return nil
}
