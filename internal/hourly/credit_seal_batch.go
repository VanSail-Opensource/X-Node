package hourly

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// SealBatch commits frozen credit partitions with one journal durability
// barrier. No proof or marker change is published unless the entire batch is
// valid and its atomic write succeeds. Existing final proofs are only replayed.
func (s *CreditStore) SealBatch(ctx context.Context, candidates []SealCandidate) ([]protocol.HourlyCreditProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(candidates) > creditJournalMaxObligations {
		return nil, ErrCreditCapacity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.Healthy() {
		return nil, ErrCreditUnavailable
	}
	next := s.snapshot()
	proofs := make([]protocol.HourlyCreditProof, 0, len(candidates))
	seen := make(map[string]bool, len(candidates))
	changed := false
	for _, candidate := range candidates {
		id := candidate.credit.install.ReservationID
		if seen[id] {
			return nil, ErrCreditScope
		}
		seen[id] = true
		i, proof, err := s.candidateProof(candidate)
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, proof)
		if next.Records[i].Proof == nil {
			next.Records[i].Proof = &proof
			changed = true
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if changed {
		if err := s.persist(next); err != nil {
			return nil, err
		}
		for _, candidate := range candidates {
			candidate.credit.marker.invalidate()
		}
	}
	return proofs, nil
}
