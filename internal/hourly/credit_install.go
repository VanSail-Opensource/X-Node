package hourly

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Install commits the immutable reservation before returning activation authority.
// An identical live retry shares its one-shot marker; recovered/retired installs
// can only replay their final proof and never become spendable again.
func (s *CreditStore) Install(ctx context.Context, install protocol.HourlyCreditInstall) (InstalledCredit, error) {
	if err := ctx.Err(); err != nil {
		return InstalledCredit{}, err
	}
	if err := protocol.ValidateHourlyInstall(install); err != nil {
		return InstalledCredit{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return InstalledCredit{}, err
	}
	if !s.Healthy() {
		return InstalledCredit{}, ErrCreditUnavailable
	}
	digest := protocol.HourlyInstallDigest(install)
	if i := s.record(install.ReservationID); i >= 0 {
		record := s.data.Records[i]
		if record.Digest != digest {
			return InstalledCredit{}, ErrCreditScope
		}
		marker := s.markers[install.ReservationID]
		if record.Proof != nil || marker == nil {
			return InstalledCredit{}, ErrCreditReplay
		}
		return InstalledCredit{install: record.Install, digest: digest, marker: marker}, nil
	}
	if s.tombstone(install.ReservationID) >= 0 || install.IssueSequence <= s.data.HighWater {
		return InstalledCredit{}, ErrCreditReplay
	}
	if s.data.AgentID != "" && s.data.AgentID != install.AgentID {
		return InstalledCredit{}, ErrCreditScope
	}
	if len(s.data.Records) >= creditJournalMaxObligations {
		s.failClosed()
		return InstalledCredit{}, ErrCreditCapacity
	}
	next := s.snapshot()
	next.AgentID, next.HighWater = install.AgentID, install.IssueSequence
	next.Records = append(next.Records, creditRecord{Install: install, Digest: digest})
	if err := s.persist(next); err != nil {
		return InstalledCredit{}, err
	}
	marker := newCreditMarker(s)
	s.markers[install.ReservationID] = marker
	return InstalledCredit{install: install, digest: digest, marker: marker}, nil
}
