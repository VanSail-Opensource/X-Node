package hourly

import (
	stdjson "encoding/json"
	json "encoding/json/v2"
	"errors"
	"math"
	"os"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// OpenCreditStore uses a dedicated private file under the agent's single-writer
// state directory. Errors return a disabled handle and preserve the original.
func OpenCreditStore(path string) (*CreditStore, error) {
	s := &CreditStore{path: path, markers: map[string]*creditInstallMarker{}, write: writeCreditFile, data: creditJournal{Version: creditJournalVersion}}
	if path == "" {
		return s, ErrCreditDurability
	}
	if err := prepareCreditDirectory(path); err != nil {
		return s, err
	}
	raw, err := readCreditFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err = s.persist(s.data); err != nil {
			return s, err
		}
		s.healthy.Store(true)
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var journal creditJournal
	if json.Unmarshal(raw, &journal, json.RejectUnknownMembers(true)) != nil || validateCreditJournal(journal) != nil {
		return s, ErrCreditCorrupt
	}
	checksummed := journal.Digest != ""
	if checksummed && (!validCreditDigest(journal.Digest) || journal.Digest != creditJournalDigest(journal)) {
		return s, ErrCreditCorrupt
	}
	// Earlier private journals lacked either ACK compaction or whole-document
	// integrity. Their sequence gaps cannot authorize unused-credit proofs.
	var metadata struct {
		RetiredThrough *uint64 `json:"retired_through,string"`
	}
	if stdjson.Unmarshal(raw, &metadata) != nil {
		return s, ErrCreditCorrupt
	}
	changed := !checksummed || metadata.RetiredThrough == nil
	if changed {
		journal.RetiredThrough = journal.HighWater
	}
	s.data = journal
	next := s.snapshot()
	for i, record := range next.Records {
		if record.Proof != nil {
			continue
		}
		// Per-payload admission is intentionally memory-only. The master may have
		// stronger live progress, but a restart cannot prove any residual unused.
		proof := protocol.HourlyCreditProof{Install: record.Install, UnknownBytes: record.Install.ByteCeiling, Recovery: true}
		proof.Digest = protocol.HourlyProofDigest(proof)
		next.Records[i].Proof = &proof
		changed = true
	}
	if changed {
		if err = s.persist(next); err != nil {
			return s, err
		}
	}
	s.publishIdentity(s.data)
	s.healthy.Store(true)
	return s, nil
}

// Recovery returns only durable final proofs, still bound to their original
// install's agent, boot and control session. Callers must frame bounded batches.
func (s *CreditStore) Recovery() []protocol.HourlyCreditProof {
	s.mu.Lock()
	defer s.mu.Unlock()
	proofs := make([]protocol.HourlyCreditProof, 0, len(s.data.Records))
	for _, record := range s.data.Records {
		if record.Proof != nil {
			proofs = append(proofs, *record.Proof)
		}
	}
	return proofs
}

func validateCreditJournal(j creditJournal) error {
	if j.Version != creditJournalVersion || j.HighWater > math.MaxInt64 || j.RetiredThrough > j.HighWater || len(j.Records) > creditJournalMaxObligations || len(j.Tombstones) > creditJournalMaxTombstones {
		return ErrCreditCorrupt
	}
	if j.HighWater == 0 {
		if j.AgentID != "" || len(j.Records)+len(j.Tombstones) != 0 {
			return ErrCreditCorrupt
		}
		return nil
	}
	if !protocol.ValidStreamID(j.AgentID) {
		return ErrCreditCorrupt
	}
	ids, sequences := map[string]bool{}, map[uint64]bool{}
	highest, previous := j.RetiredThrough, uint64(0)
	for _, record := range j.Records {
		install := record.Install
		if protocol.ValidateHourlyInstall(install) != nil || install.AgentID != j.AgentID || record.Digest != protocol.HourlyInstallDigest(install) || install.IssueSequence <= previous || install.IssueSequence > j.HighWater || ids[install.ReservationID] {
			return ErrCreditCorrupt
		}
		if proof := record.Proof; proof != nil {
			if proof.Install != install || protocol.ValidateHourlyProof(*proof) != nil || proof.Digest != protocol.HourlyProofDigest(*proof) || proof.Recovery && (proof.UnknownBytes != install.ByteCeiling || proof.UnusedBytes != 0 || proof.AdmittedUploadBytes != 0 || proof.AdmittedDownloadBytes != 0) || !proof.Recovery && proof.UnknownBytes != 0 {
				return ErrCreditCorrupt
			}
		}
		ids[install.ReservationID], sequences[install.IssueSequence] = true, true
		previous, highest = install.IssueSequence, max(highest, install.IssueSequence)
	}
	previous = 0
	for _, tombstone := range j.Tombstones {
		ack := protocol.HourlyCreditAck{ReservationID: tombstone.ReservationID, IssueSequence: tombstone.IssueSequence, Digest: tombstone.ProofDigest}
		if protocol.ValidateHourlyAck(ack) != nil || tombstone.IssueSequence <= previous || tombstone.IssueSequence > j.HighWater || ids[tombstone.ReservationID] || sequences[tombstone.IssueSequence] || !validCreditDigest(tombstone.InstallDigest) || !validCreditDigest(tombstone.ProofDigest) {
			return ErrCreditCorrupt
		}
		ids[tombstone.ReservationID], sequences[tombstone.IssueSequence] = true, true
		previous, highest = tombstone.IssueSequence, max(highest, tombstone.IssueSequence)
	}
	if highest != j.HighWater {
		return ErrCreditCorrupt
	}
	return nil
}

func validCreditDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
