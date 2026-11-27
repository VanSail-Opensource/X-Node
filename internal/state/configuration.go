package state

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// Metadata is a value-only observation; it never copies credentials or journals.
type Metadata struct {
	AgentID                  string
	Revision, ConfigRevision uint64
	HasConfig                bool
}

func (s *Store) Metadata() Metadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Metadata{s.data.AgentID, s.data.Revision, s.data.ConfigRevision, s.data.Config != nil}
}

func (s *Store) Revision() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Revision
}

// Users is the detached authorization baseline for a user delta, without
// copying either native configuration or unrelated journals.
func (s *Store) Users() []protocol.User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return protocol.Clone(s.data.Users)
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
