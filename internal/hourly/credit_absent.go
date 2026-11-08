package hourly

import (
	"context"
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// SealAbsent proves that an exact reserved obligation never entered this
// persistent agent. Retained records/tombstones cover every issued sequence
// above RetiredThrough; missing evidence at/below that floor stays uncertain.
func (s *CreditStore) SealAbsent(ctx context.Context, expected protocol.HourlyCreditInstall) (protocol.HourlyCreditProof, error) {
	if err := ctx.Err(); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if protocol.ValidateHourlyInstall(expected) != nil {
		return protocol.HourlyCreditProof{}, ErrCreditScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if !s.Healthy() {
		return protocol.HourlyCreditProof{}, ErrCreditUnavailable
	}
	if s.data.AgentID != "" && s.data.AgentID != expected.AgentID {
		return protocol.HourlyCreditProof{}, ErrCreditScope
	}
	digest := protocol.HourlyInstallDigest(expected)
	if index := s.record(expected.ReservationID); index >= 0 {
		record := s.data.Records[index]
		if record.Digest != digest {
			return protocol.HourlyCreditProof{}, ErrCreditScope
		}
		if record.Proof == nil {
			return protocol.HourlyCreditProof{}, ErrCreditReplay
		}
		return *record.Proof, nil
	}
	proof := protocol.HourlyCreditProof{Install: expected, UnusedBytes: expected.ByteCeiling}
	proof.Digest = protocol.HourlyProofDigest(proof)
	if index := s.tombstone(expected.ReservationID); index >= 0 {
		tombstone := s.data.Tombstones[index]
		if tombstone.InstallDigest != digest {
			return protocol.HourlyCreditProof{}, ErrCreditScope
		}
		// An exact known unused proof can be reconstructed; a different partition
		// cannot be inferred from an acknowledged digest.
		if tombstone.ProofDigest == proof.Digest {
			return proof, nil
		}
		return protocol.HourlyCreditProof{}, ErrCreditReplay
	}
	for _, record := range s.data.Records {
		if record.Install.IssueSequence == expected.IssueSequence {
			return protocol.HourlyCreditProof{}, ErrCreditScope
		}
	}
	for _, tombstone := range s.data.Tombstones {
		if tombstone.IssueSequence == expected.IssueSequence {
			return protocol.HourlyCreditProof{}, ErrCreditScope
		}
	}
	if expected.IssueSequence <= s.data.RetiredThrough {
		return protocol.HourlyCreditProof{}, ErrCreditReplay
	}
	if len(s.data.Records) >= creditJournalMaxObligations {
		s.failClosed()
		return protocol.HourlyCreditProof{}, ErrCreditCapacity
	}
	next := s.snapshot()
	next.AgentID = expected.AgentID
	next.HighWater = max(next.HighWater, expected.IssueSequence)
	next.Records = append(next.Records, creditRecord{Install: expected, Digest: digest, Proof: &proof})
	sort.Slice(next.Records, func(i, j int) bool {
		return next.Records[i].Install.IssueSequence < next.Records[j].Install.IssueSequence
	})
	if err := s.persist(next); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	return proof, nil
}
