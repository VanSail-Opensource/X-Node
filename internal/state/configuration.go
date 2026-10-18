package state

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

func (s *Store) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Revision
}

// Configuration avoids cloning accounting and traffic journals for a utility job.
func (s *Store) Configuration() (protocol.Config, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Config == nil {
		return protocol.Config{}, false
	}
	return protocol.Clone(*s.data.Config), true
}
