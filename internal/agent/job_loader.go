package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func NewJobs(dir string, send func(protocol.Message, bool) bool) (*Jobs, error) {
	j := &Jobs{path: filepath.Join(dir, "jobs.json"), running: map[string]runningJob{}, slots: make(chan struct{}, 2), urgent: make(chan struct{}, 1), send: send, write: writeJobFile}
	if err := j.loadHistory(); err != nil {
		j.recovery = err.Error()
	}
	// Uncertain journal metadata restricts durable utilities, not agent startup,
	// ordinary runtime or the actor's accounting/traffic-ACK handling.
	return j, nil
}

func (j *Jobs) loadHistory() error {
	info, err := os.Lstat(j.path)
	if os.IsNotExist(err) {
		found, inspectErr := j.hasEvidence()
		if inspectErr != nil || found {
			return errors.New("JOURNAL_PRIMARY_MISSING: preserve evidence and review missing history")
		}
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("JOURNAL_UNREADABLE: preserve history and review its file")
	}
	if info.Size() > legacyJobRecoveryMaxBytes {
		return errors.New("JOURNAL_RECOVERY_LIMIT: history exceeds bounded recovery capacity")
	}
	file, err := os.Open(j.path)
	if err != nil {
		return errors.New("JOURNAL_UNREADABLE: history could not be opened")
	}
	defer file.Close()
	var entries []JobResult
	digest := sha256.New()
	metadataOnly := info.Size() >= maxJobJournalBytes
	if metadataOnly {
		entries, err = readLegacyJobMetadata(io.TeeReader(file, digest))
	} else {
		var raw []byte
		raw, err = io.ReadAll(io.LimitReader(file, maxJobJournalBytes))
		if err == nil && int64(len(raw)) != info.Size() {
			err = errLegacyJobMetadata
		}
		if err == nil {
			_, err = readLegacyJobMetadata(bytes.NewReader(raw))
		}
		if err == nil {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			var receipts []journalJobResult
			err = decoder.Decode(&receipts)
			for _, receipt := range receipts {
				receipt.JobResult.terminalFailure = receipt.TerminalFailure
				entries = append(entries, receipt.JobResult)
			}
		}
		_, _ = digest.Write(raw)
	}
	if err != nil {
		return errors.New("JOURNAL_INVALID: history identities could not be verified")
	}
	preserve := metadataOnly
	var history []JobResult
	for _, entry := range durableJobHistory(entries) {
		if metadataOnly || entry.Status == "running" || entry.Status == "cancelled" || entry.Status == "failed" && !entry.terminalFailure {
			preserve = true
			entry.Status, entry.Error = "uncertain", "recovered mutation requires native outcome reconciliation"
		}
		if protectedJob(entry) && entry.Data != nil {
			preserve = true
		}
		normalized := boundedJobResult(entry)
		if normalized.Status != entry.Status {
			preserve = true
		}
		history, err = retainJob(history, normalized, true)
		if err != nil {
			return errors.New("JOURNAL_CAPACITY: uncertain identities exceed safe receipt capacity")
		}
	}
	if preserve {
		if err := j.preserveEvidence(file, info, digest.Sum(nil)); err != nil {
			return errors.New("JOURNAL_EVIDENCE: original history could not be preserved")
		}
	}
	if err := j.writeHistory(history); err != nil {
		return errors.New("JOURNAL_COMPACTION: verified history could not be persisted")
	}
	j.history = history
	return nil
}

func (j *Jobs) hasEvidence() (bool, error) {
	directory, err := os.Open(filepath.Dir(j.path))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer directory.Close()
	for {
		names, err := directory.Readdirnames(128)
		for _, name := range names {
			if strings.HasPrefix(name, filepath.Base(j.path)+".legacy-") {
				return true, nil
			}
		}
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}
