package agent

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type JobResult struct {
	ID              string    `json:"id"`
	Command         string    `json:"command"`
	Status          string    `json:"status"`
	Data            any       `json:"data,omitempty"`
	Error           string    `json:"error,omitempty"`
	Finished        time.Time `json:"finished,omitempty"`
	encodedBytes    int
	terminalFailure bool // Private journal evidence; never changes command.result.
}

type journalJobResult struct {
	JobResult
	TerminalFailure bool `json:"terminal_failure,omitempty"`
}

type Jobs struct {
	mu           sync.Mutex
	persistMu    sync.Mutex // Workers only; never acquired by the control reader.
	path         string
	running      map[string]runningJob
	history      []JobResult
	observations []JobResult
	recovery     string
	slots        chan struct{}
	urgent       chan struct{}
	send         func(protocol.Message, bool) bool
	redact       func(string) string
	write        func(string, []byte, os.FileMode) error
}

type runningJob struct {
	command string
	cancel  context.CancelFunc
}

func (j *Jobs) Start(ctx context.Context, id, command string, fn func(context.Context, func(any)) (any, error)) error {
	return j.start(ctx, id, command, false, fn)
}

// StartControl reserves one executor slot for urgent control work.
func (j *Jobs) StartControl(ctx context.Context, id, command string, fn func(context.Context, func(any)) (any, error)) error {
	return j.start(ctx, id, command, true, fn)
}

func (j *Jobs) start(ctx context.Context, id, command string, urgent bool, fn func(context.Context, func(any)) (any, error)) error {
	if id == "" || len(id) > 128 || command == "" || len(command) > 64 || strings.ContainsAny(id+command, "\x00\r\n") {
		return errors.New("invalid utility command identity")
	}
	j.mu.Lock()
	if running, ok := j.running[id]; ok {
		j.mu.Unlock()
		if running.command != command {
			return errors.New("request ID was reused for another command")
		}
		j.send(protocol.New("command.accepted", id, 0, map[string]string{"command": command}), true)
		return nil
	}
	for _, history := range [][]JobResult{j.history, j.observations} {
		for _, result := range history {
			if result.ID != id {
				continue
			}
			j.mu.Unlock()
			if result.Command != command {
				return errors.New("request ID was reused for another command")
			}
			j.send(protocol.New("command.result", id, 0, result), true)
			return nil
		}
	}
	if j.recovery != "" && persistentJob(command) {
		j.mu.Unlock()
		return errors.New("job history recovery required; durable command was not executed")
	}
	slots := j.slots
	if urgent {
		slots = j.urgent
	}
	select {
	case slots <- struct{}{}:
	default:
		j.mu.Unlock()
		return errors.New("utility workers are busy")
	}
	child, cancel := context.WithCancel(ctx)
	j.running[id] = runningJob{command: command, cancel: cancel}
	j.mu.Unlock()
	j.send(protocol.New("command.accepted", id, 0, map[string]string{"command": command}), true)
	go j.execute(child, cancel, slots, id, command, fn)
	return nil
}

func (j *Jobs) Cancel(id string) bool {
	j.mu.Lock()
	job := j.running[id]
	j.mu.Unlock()
	if job.cancel == nil {
		return false
	}
	job.cancel()
	return true
}

func (j *Jobs) Snapshot() []JobResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]JobResult, 0, len(j.history)+len(j.observations)+len(j.running)+1)
	for _, history := range [][]JobResult{j.history, j.observations} {
		for _, result := range history {
			if _, active := j.running[result.ID]; !active {
				out = append(out, cloneJobResult(result))
			}
		}
	}
	for id, job := range j.running {
		out = append(out, JobResult{ID: id, Command: job.command, Status: "running"})
	}
	if j.recovery != "" {
		out = append(out, JobResult{ID: "journal-recovery-required", Command: "journal.recovery", Status: "uncertain", Error: j.recovery})
	}
	return out
}
