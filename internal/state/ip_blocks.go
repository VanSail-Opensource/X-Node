package state

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const maxIPBlocks = 4096

// BlockIP preserves scoped key-only unblocks while requiring a current positive
// subject. Agent commands use BlockIPView with their explicitly captured subject.
func (s *Store) BlockIP(key string, block protocol.IPBlock) error {
	user, address, ok := strings.Cut(key, ":")
	id, err := strconv.Atoi(user)
	if !ok || err != nil || id < 0 {
		return errors.New("invalid IP block key")
	}
	if block.SourceIP == "" {
		block.SourceIP = address
	}
	if block.UserID == 0 {
		block.UserID = id
	}
	var expected *protocol.User
	if id > 0 {
		current, _, err := s.SubjectView(id)
		if err != nil {
			return err
		}
		expected = &current
	}
	_, err = s.BlockIPView(key, block, expected)
	return err
}

// BlockIPView validates the captured subject and commits a complete admission
// view. A nil expected subject permits only the global (zero-user) scope.
func (s *Store) BlockIPView(key string, block protocol.IPBlock, expected *protocol.User) (AuthorizationView, error) {
	address, err := netip.ParseAddr(block.SourceIP)
	if err != nil || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" || block.UserID < 0 {
		return AuthorizationView{}, errors.New("invalid IP block subject or address")
	}
	block.SourceIP = address.Unmap().String()
	if key != protocol.IPBlockKey(block.UserID, block.SourceIP) {
		return AuthorizationView{}, errors.New("invalid IP block key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if block.UserID == 0 {
		if expected != nil {
			return AuthorizationView{}, ErrAuthorizationSubject
		}
	} else {
		valid := false
		for _, current := range s.data.Users {
			if expected != nil && current.ID == block.UserID && len(current.InboundTags) > 0 && expected.ID == current.ID && protocol.SameUserIdentity(current, *expected) {
				valid = true
				break
			}
		}
		if !valid {
			return AuthorizationView{}, ErrAuthorizationSubject
		}
	}
	old, exists := s.data.IPBlocks[key]
	if block.Until.IsZero() && !exists || exists && old.UserID == block.UserID && old.SourceIP == block.SourceIP && old.Until.Equal(block.Until) {
		return s.authorizationViewLocked(), nil
	}
	if !exists && !block.Until.IsZero() && len(s.data.IPBlocks) >= maxIPBlocks {
		return AuthorizationView{}, errors.New("IP block capacity exhausted")
	}
	next := protocol.Clone(s.data)
	if block.Until.IsZero() {
		delete(next.IPBlocks, key)
	} else {
		if next.IPBlocks == nil {
			next.IPBlocks = make(map[string]protocol.IPBlock)
		}
		next.IPBlocks[key] = block
	}
	return s.commitAuthorizationLocked(next)
}

// ExpireIPBlocks compares the currently persisted deadlines under the store lock;
// a delayed sweep cannot erase a block extended past its captured cutoff.
// No eligible expiry returns a zero view without cloning or writing state.
func (s *Store) ExpireIPBlocks(cutoff time.Time) (AuthorizationView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, block := range s.data.IPBlocks {
		if !block.Until.After(cutoff) {
			found = true
			break
		}
	}
	if !found {
		return AuthorizationView{}, nil
	}
	next := protocol.Clone(s.data)
	for key, block := range next.IPBlocks {
		if !block.Until.After(cutoff) {
			delete(next.IPBlocks, key)
		}
	}
	return s.commitAuthorizationLocked(next)
}
