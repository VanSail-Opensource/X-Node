package agent

import "errors"

// Only executor workers enter this mutex. Disk waits never own the control
// reader's registry mutex or delay traffic acknowledgments/recovery inspection.
func (j *Jobs) recordIntent(id, command string) error {
	j.persistMu.Lock()
	defer j.persistMu.Unlock()
	intent := boundedJobResult(JobResult{ID: id, Command: command, Status: "uncertain", Error: "mutation outcome pending"})
	j.mu.Lock()
	next, err := retainJob(j.history, intent, true)
	j.mu.Unlock()
	if err != nil {
		return err
	}
	if err := j.writeHistory(next); err != nil {
		return err
	}
	j.mu.Lock()
	j.history = next
	j.mu.Unlock()
	return nil
}

func (j *Jobs) recordCompletion(result JobResult) JobResult {
	j.persistMu.Lock()
	defer j.persistMu.Unlock()
	j.mu.Lock()
	next, err := retainJob(j.history, result, true)
	j.mu.Unlock()
	if err == nil {
		err = j.writeHistory(next)
	}
	if err != nil {
		result.Status, result.Error = "uncertain", "job result persistence failed; native reconciliation required"
		result = boundedJobResult(result)
		j.mu.Lock()
		next, _ = retainJob(j.history, result, true)
		j.mu.Unlock()
	}
	j.mu.Lock()
	if next != nil {
		j.history = next
	}
	j.mu.Unlock()
	return result
}

func (j *Jobs) writeHistory(history []JobResult) error {
	if len(history) > maxJobHistory {
		return errJobCapacity
	}
	raw, err := marshalJobBounded(durableJobHistory(history), maxJobJournalBytes-1)
	if err != nil {
		return err
	}
	if len(raw) >= maxJobJournalBytes {
		return errors.New("job journal byte capacity exhausted")
	}
	return j.write(j.path, raw, 0600)
}
