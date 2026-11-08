package state

import (
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// AuthorizationView is a detached, immutable publication of committed admission
// state. Sequence orders publications within one process; Revision is the
// persisted master authorization revision. Neither field is a traffic sequence.
type AuthorizationView struct {
	Sequence uint64
	Revision uint64
	Users    []protocol.User
	IPBlocks map[string]protocol.IPBlock
}

// ErrAuthorizationSubject rejects stale IP commands instead of applying them
// to a removed, replaced or independently renewed identity.
var ErrAuthorizationSubject = errors.New("IP control subject changed or unavailable")

// CurrentAuthorization returns a detached startup/publication snapshot.
func (s *Store) CurrentAuthorization() AuthorizationView {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizationViewLocked()
}

func (s *Store) authorizationViewLocked() AuthorizationView {
	return AuthorizationView{Sequence: s.authorizationSequence, Revision: s.data.Revision,
		Users: protocol.Clone(s.data.Users), IPBlocks: protocol.Clone(s.data.IPBlocks)}
}

// SubjectView captures a positive active subject and the same committed view.
// IP mutations must still compare this credential/period identity under lock.
func (s *Store) SubjectView(id int) (protocol.User, AuthorizationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.data.Users {
		if id > 0 && user.ID == id && len(user.InboundTags) > 0 {
			return protocol.Clone(user), s.authorizationViewLocked(), nil
		}
	}
	return protocol.User{}, AuthorizationView{}, ErrAuthorizationSubject
}

// Authorize preserves the original error-only interface.
func (s *Store) Authorize(users []protocol.User, revision uint64) error {
	_, err := s.AuthorizeView(users, revision)
	return err
}

// AuthorizeView remaps existing scoped restrictions and authorization in one
// durable change. All transfers are derived from the original user snapshot.
func (s *Store) AuthorizeView(users []protocol.User, revision uint64) (AuthorizationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision <= s.data.Revision {
		return AuthorizationView{}, errors.New("stale revision")
	}
	nextUsers := protocol.Clone(users)
	if nextUsers == nil {
		nextUsers = []protocol.User{}
	}
	replacements, err := protocol.UserReplacementIDs(s.data.Users, nextUsers)
	if err != nil {
		return AuthorizationView{}, err
	}
	next := protocol.Clone(s.data)
	next.IPBlocks = protocol.RemapIPBlocks(s.data.IPBlocks, replacements)
	next.Users, next.Revision, next.DesiredConfig = nextUsers, revision, nil
	return s.commitAuthorizationLocked(next)
}

// The caller owns mu. Failed persistence cannot publish a new sequence or view.
func (s *Store) commitAuthorizationLocked(next Data) (AuthorizationView, error) {
	if s.authorizationSequence == ^uint64(0) {
		return AuthorizationView{}, errors.New("authorization publication sequence exhausted")
	}
	if err := s.persist(next); err != nil {
		return AuthorizationView{}, err
	}
	s.data = next
	s.authorizationSequence++
	return s.authorizationViewLocked(), nil
}
