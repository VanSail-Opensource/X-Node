package agent

import "errors"

// Only executor workers enter this mutex. Disk waits never own the control
// reader's registry mutex or delay traffic acknowledgments/recovery inspection.
func (j *Jobs) recordIntent(id, command string) error {
	j.persistMu.Lock()
	defer j.persistMu.Unlock()
	intent := boundedJobResult(JobResult{ID: id, Command: command, Status: "uncertain", Error: "mutation outcome pending"})
	j.mu.Lock()
	next, evicted, err := retainJobWithEvictions(j.history, intent, true)
	j.mu.Unlock()
	if err != nil {
		return err
	}
	if err := j.writeHistory(next); err != nil {
		return err
	}
	j.mu.Lock()
	j.history = next
	j.historyIndex = indexRetainedJob(j.historyIndex, intent, evicted)
	j.mu.Unlock()
	return nil
}

func (j *Jobs) recordCompletion(result JobResult) JobResult {
	j.persistMu.Lock()
	defer j.persistMu.Unlock()
	j.mu.Lock()
	next, evicted, err := retainJobWithEvictions(j.history, result, true)
	j.mu.Unlock()
	if err == nil {
		err = j.writeHistory(next)
	}
	if err != nil {
		result.Status, result.Error = "uncertain", "job result persistence failed; native reconciliation required"
		result = boundedJobResult(result)
		j.mu.Lock()
		next, evicted, _ = retainJobWithEvictions(j.history, result, true)
		j.mu.Unlock()
	}
	j.mu.Lock()
	if next != nil {
		j.history = next
		j.historyIndex = indexRetainedJob(j.historyIndex, result, evicted)
	}
	j.mu.Unlock()
	return result
}

func (j *Jobs) writeHistory(history []JobResult) error {
	raw, err := encodeJobHistory(history)
	if err != nil {
		return err
	}
	return j.write(j.path, raw, 0600)
}

func encodeJobHistory(history []JobResult) ([]byte, error) {
	if len(history) > maxJobHistory {
		return nil, errJobCapacity
	}
	receipts := make([]journalJobResult, 0, len(history))
	for _, result := range durableJobHistory(history) {
		receipts = append(receipts, journalJobResult{JobResult: result, TerminalFailure: result.terminalFailure})
	}
	raw, err := marshalJobBounded(receipts, maxJobJournalBytes-1)
	if err != nil {
		return nil, err
	}
	if len(raw) >= maxJobJournalBytes {
		return nil, errors.New("job journal byte capacity exhausted")
	}
	return raw, nil
}
