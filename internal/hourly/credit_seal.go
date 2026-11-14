package hourly

import (
	"context"
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Seal durably publishes the confirmed admitted/unused partition captured while
// the controller froze this credit. Native writer outcome never changes it.
func (s *CreditStore) Seal(ctx context.Context, candidate SealCandidate) (protocol.HourlyCreditProof, error) {
	if err := ctx.Err(); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if !s.Healthy() {
		return protocol.HourlyCreditProof{}, ErrCreditUnavailable
	}
	return s.sealCandidate(candidate)
}

// SealUnclaimed proves that a durable install rejected before controller
// admission was unused. Claiming its one-shot marker excludes every controller;
// after that linearization, complete the durable proof even if ctx is cancelled.
func (s *CreditStore) SealUnclaimed(ctx context.Context, credit InstalledCredit) (protocol.HourlyCreditProof, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if !s.Healthy() {
		return protocol.HourlyCreditProof{}, ErrCreditUnavailable
	}
	if _, err := s.creditRecord(credit); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if !credit.marker.claim() {
		return protocol.HourlyCreditProof{}, ErrCreditReplay
	}
	return s.sealCandidate(SealCandidate{credit: credit, unused: credit.install.ByteCeiling})
}

func (s *CreditStore) creditRecord(credit InstalledCredit) (int, error) {
	i := s.record(credit.install.ReservationID)
	if i < 0 || credit.marker == nil || credit.marker.store != s || s.markers[credit.install.ReservationID] != credit.marker || s.data.Records[i].Digest != credit.digest || protocol.HourlyInstallDigest(credit.install) != credit.digest {
		return 0, ErrCreditScope
	}
	return i, nil
}

func (s *CreditStore) sealCandidate(candidate SealCandidate) (protocol.HourlyCreditProof, error) {
	i, proof, err := s.candidateProof(candidate)
	if err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	if s.data.Records[i].Proof != nil {
		return proof, nil
	}
	next := s.snapshot()
	next.Records[i].Proof = &proof
	if err := s.persist(next); err != nil {
		return protocol.HourlyCreditProof{}, err
	}
	candidate.credit.marker.invalidate()
	return proof, nil
}

// candidateProof requires s.mu and never changes a record or its authority.
func (s *CreditStore) candidateProof(candidate SealCandidate) (int, protocol.HourlyCreditProof, error) {
	credit := candidate.credit
	i, err := s.creditRecord(credit)
	if err != nil {
		return 0, protocol.HourlyCreditProof{}, err
	}
	if !credit.marker.claimed.Load() {
		return 0, protocol.HourlyCreditProof{}, ErrCreditReplay
	}
	ceiling := credit.install.ByteCeiling
	if candidate.admitted[0] > ceiling || candidate.admitted[1] > ceiling-candidate.admitted[0] || candidate.unused != ceiling-candidate.admitted[0]-candidate.admitted[1] {
		return 0, protocol.HourlyCreditProof{}, ErrCreditScope
	}
	proof := protocol.HourlyCreditProof{Install: credit.install, AdmittedUploadBytes: candidate.admitted[0], AdmittedDownloadBytes: candidate.admitted[1], UnusedBytes: candidate.unused}
	proof.Digest = protocol.HourlyProofDigest(proof)
	if err := protocol.ValidateHourlyProof(proof); err != nil {
		return 0, protocol.HourlyCreditProof{}, err
	}
	if previous := s.data.Records[i].Proof; previous != nil {
		if previous.Digest != proof.Digest {
			return 0, protocol.HourlyCreditProof{}, ErrCreditScope
		}
		return i, *previous, nil
	}
	return i, proof, nil
}

// Ack retires only an exact final proof, preserving bounded replay tombstones.
func (s *CreditStore) Ack(ctx context.Context, ack protocol.HourlyCreditAck) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := protocol.ValidateHourlyAck(ack); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.Healthy() {
		return ErrCreditUnavailable
	}
	if i := s.tombstone(ack.ReservationID); i >= 0 {
		t := s.data.Tombstones[i]
		if t.IssueSequence == ack.IssueSequence && t.ProofDigest == ack.Digest {
			return nil
		}
		return ErrCreditScope
	}
	i := s.record(ack.ReservationID)
	if i < 0 {
		return ErrCreditReplay
	}
	record := s.data.Records[i]
	if record.Proof == nil || record.Install.IssueSequence != ack.IssueSequence || record.Proof.Digest != ack.Digest {
		return ErrCreditScope
	}
	next := s.snapshot()
	next.Records = append(next.Records[:i], next.Records[i+1:]...)
	next.Tombstones = append(next.Tombstones, creditTombstone{ReservationID: ack.ReservationID, IssueSequence: ack.IssueSequence, InstallDigest: record.Digest, ProofDigest: ack.Digest})
	sort.Slice(next.Tombstones, func(i, j int) bool { return next.Tombstones[i].IssueSequence < next.Tombstones[j].IssueSequence })
	if len(next.Tombstones) > creditJournalMaxTombstones {
		for _, retired := range next.Tombstones[:len(next.Tombstones)-creditJournalMaxTombstones] {
			next.RetiredThrough = max(next.RetiredThrough, retired.IssueSequence)
		}
		next.Tombstones = next.Tombstones[len(next.Tombstones)-creditJournalMaxTombstones:]
	}
	if err := s.persist(next); err != nil {
		return err
	}
	delete(s.markers, ack.ReservationID)
	return nil
}
