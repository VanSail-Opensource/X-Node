package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (j *Jobs) execute(ctx context.Context, cancel context.CancelFunc, slots chan struct{}, id, command string, fingerprint [sha256.Size]byte, fn func(context.Context, func(any)) (any, error)) {
	release := sync.OnceFunc(func() { <-slots; cancel() })
	defer release()
	publish := func(result JobResult) {
		// Finish receipt bookkeeping and payload encoding before admitting a
		// successor. The bounded send callback must not wait for network I/O.
		message := protocol.New("command.result", id, 0, result)
		release()
		j.send(message, true)
	}
	result := JobResult{ID: id, Command: command, Status: "completed", fingerprint: fingerprint}
	if ctx.Err() != nil {
		result.Status, result.Error = "cancelled", "job cancelled before execution"
		publish(j.finishVolatile(boundedJobResult(result)))
		return
	}
	if persistentJob(command) {
		if err := j.recordIntent(id, command); err != nil {
			result.Status, result.Error, result.Finished = "failed", "job intent persistence failed; command was not executed", time.Now().UTC()
			if errors.Is(err, errJobCapacity) {
				result.Error = "job receipt capacity exhausted; command was not executed"
			}
			publish(j.finishVolatile(boundedJobResult(result)))
			return
		}
	}
	progress := func(data any) { j.send(protocol.New("command.progress", id, 0, data), false) }
	var data any
	err := ctx.Err()
	executed := err == nil
	if executed {
		data, err = fn(ctx, progress)
	}
	result.Data, result.Finished = data, time.Now().UTC()
	if err != nil {
		result.Status, result.Error = "failed", "utility operation failed"
		if persistentJob(command) && !definiteJobRefusal(err) {
			result.Status, result.Error = "uncertain", "mutation failed; native outcome reconciliation required"
		}
		if j.redact != nil {
			result.Error = j.redact(err.Error())
		}
	}
	if !executed {
		result.Status, result.Error = "failed", "job cancelled before execution"
	} else if !definiteJobRefusal(err) && (ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		result.Status = "cancelled"
		if persistentJob(command) {
			result.Status, result.Error = "uncertain", "cancelled mutation requires native outcome reconciliation"
		}
	}
	result.terminalFailure = result.Status == "failed" && (!executed || definiteJobRefusal(err))
	if persistentJob(command) {
		result = j.recordCompletion(boundedJobResult(result))
	} else {
		publish(j.finishVolatile(wireJobResult(result)))
		return
	}
	j.mu.Lock()
	delete(j.running, id)
	j.mu.Unlock()
	publish(result)
}

func (j *Jobs) finishVolatile(result JobResult) JobResult {
	remember := result
	if result.encodedBytes > maxJobResultBytes && !observationJob(result.Command) {
		result.Status, result.Error, result.Data = "uncertain", "volatile result exceeded its safe replay limit", nil
		result = boundedJobResult(result)
		remember = result
	}
	j.mu.Lock()
	delete(j.running, result.ID)
	// Large read results can be returned within the transport bound, but are
	// disposable: retrying that read does not require retaining the full policy.
	if remember.encodedBytes <= maxJobResultBytes {
		if next, err := retainJob(j.observations, remember, false); err == nil {
			j.observations = next
		}
	}
	j.mu.Unlock()
	return result
}
