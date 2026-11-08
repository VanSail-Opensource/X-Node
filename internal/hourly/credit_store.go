package hourly

import (
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const (
	creditJournalVersion        = 1
	creditJournalMaxObligations = 1024
	creditJournalMaxTombstones  = 1024
)

var (
	ErrCreditUnavailable = errors.New("hourly credit store unavailable")
	ErrCreditCorrupt     = errors.New("invalid hourly credit journal; preserve original evidence")
	ErrCreditDurability  = errors.New("hourly credit durability barrier failed")
	ErrCreditCapacity    = errors.New("hourly credit journal capacity exhausted")
	ErrCreditReplay      = errors.New("hourly credit replay cannot activate capacity")
	ErrCreditScope       = errors.New("hourly credit obligation scope mismatch")
)

type creditRecord struct {
	Install protocol.HourlyCreditInstall `json:"install"`
	Digest  string                       `json:"install_digest"`
	Proof   *protocol.HourlyCreditProof  `json:"proof,omitempty"`
}

type creditTombstone struct {
	ReservationID string `json:"reservation_id"`
	IssueSequence uint64 `json:"issue_sequence,string"`
	InstallDigest string `json:"install_digest"`
	ProofDigest   string `json:"proof_digest"`
}

type creditJournal struct {
	Version        int               `json:"version"`
	Digest         string            `json:"journal_digest,omitempty"`
	AgentID        string            `json:"agent_id"`
	HighWater      uint64            `json:"high_water,string"`
	RetiredThrough uint64            `json:"retired_through,string"`
	Records        []creditRecord    `json:"records"`
	Tombstones     []creditTombstone `json:"tombstones"`
}

type creditIdentity struct {
	agentID  string
	pristine bool
}

// CreditStore retains financial obligations independently of ordinary traffic
// journals. Its failures disable hourly credit without preventing legacy startup.
type CreditStore struct {
	mu       sync.Mutex
	path     string
	data     creditJournal
	markers  map[string]*creditInstallMarker
	healthy  atomic.Bool
	identity atomic.Pointer[creditIdentity]
	write    func(string, []byte) error
}

// Healthy reports whether durable hourly mutations remain available.
func (s *CreditStore) Healthy() bool { return s != nil && s.healthy.Load() }

// MatchesAgent rejects reuse after the ordinary agent identity changes without
// waiting for persistence. Only a pristine journal may accept its first identity.
func (s *CreditStore) MatchesAgent(id string) bool {
	if s == nil || !protocol.ValidStreamID(id) {
		return false
	}
	identity := s.identity.Load()
	if identity == nil {
		return false
	}
	return identity.agentID == id || identity.pristine
}

// Close revokes all process-local activation authority. There are no open files.
func (s *CreditStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failClosed()
	return nil
}

func (s *CreditStore) failClosed() {
	s.healthy.Store(false)
	for _, marker := range s.markers {
		marker.invalidate()
	}
}

func (s *CreditStore) persist(next creditJournal) error {
	next.Digest = creditJournalDigest(next)
	raw, err := json.Marshal(next)
	if err == nil && len(raw) > creditJournalMaxBytes {
		err = ErrCreditCapacity
	}
	if err == nil {
		err = s.write(s.path, raw)
	}
	if err != nil {
		s.failClosed()
		return err
	}
	s.data = next
	s.publishIdentity(next)
	return nil
}

func (s *CreditStore) publishIdentity(journal creditJournal) {
	s.identity.Store(&creditIdentity{agentID: journal.AgentID, pristine: journal.AgentID == "" && journal.HighWater == 0 && journal.RetiredThrough == 0 && len(journal.Records) == 0 && len(journal.Tombstones) == 0})
}

func (s *CreditStore) record(id string) int {
	for i := range s.data.Records {
		if s.data.Records[i].Install.ReservationID == id {
			return i
		}
	}
	return -1
}

func (s *CreditStore) tombstone(id string) int {
	for i := range s.data.Tombstones {
		if s.data.Tombstones[i].ReservationID == id {
			return i
		}
	}
	return -1
}

func (s *CreditStore) snapshot() creditJournal {
	next := s.data
	next.Records = append([]creditRecord(nil), next.Records...)
	next.Tombstones = append([]creditTombstone(nil), next.Tombstones...)
	return next
}
