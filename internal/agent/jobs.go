package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type JobResult struct {
	ID       string    `json:"id"`
	Command  string    `json:"command"`
	Status   string    `json:"status"`
	Data     any       `json:"data,omitempty"`
	Error    string    `json:"error,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
}
type Jobs struct {
	mu      sync.Mutex
	path    string
	running map[string]context.CancelFunc
	history []JobResult
	slots   chan struct{}
	urgent  chan struct{}
	send    func(protocol.Message, bool) bool
	redact  func(string) string
}

func NewJobs(dir string, send func(protocol.Message, bool) bool) (*Jobs, error) {
	j := &Jobs{path: filepath.Join(dir, "jobs.json"), running: map[string]context.CancelFunc{}, slots: make(chan struct{}, 2), urgent: make(chan struct{}, 1), send: send}
	if b, e := os.ReadFile(j.path); e == nil {
		if len(b) >= 2<<20 || json.Unmarshal(b, &j.history) != nil {
			return nil, errors.New("invalid persisted job history")
		}
		j.history = durableJobHistory(j.history)
		cleaned, err := json.Marshal(j.history)
		if err != nil {
			return nil, err
		}
		if err = state.AtomicWrite(j.path, cleaned, 0600); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return j, nil
}
func (j *Jobs) Start(ctx context.Context, id, command string, fn func(context.Context, func(any)) (any, error)) error {
	return j.start(ctx, id, command, false, fn)
}

// StartControl reserves one existing executor slot for urgent control work.
func (j *Jobs) StartControl(ctx context.Context, id, command string, fn func(context.Context, func(any)) (any, error)) error {
	return j.start(ctx, id, command, true, fn)
}
func (j *Jobs) start(ctx context.Context, id, command string, urgent bool, fn func(context.Context, func(any)) (any, error)) error {
	if id == "" {
		return errors.New("utility commands require an ID")
	}
	j.mu.Lock()
	for _, r := range j.history {
		if r.ID == id {
			if r.Command != command {
				j.mu.Unlock()
				return errors.New("request ID was reused for another command")
			}
			j.mu.Unlock()
			j.send(protocol.New("command.result", id, 0, r), true)
			return nil
		}
	}
	if _, ok := j.running[id]; ok {
		j.mu.Unlock()
		j.send(protocol.New("command.accepted", id, 0, map[string]string{"command": command}), true)
		return nil
	}
	slots := j.slots
	if urgent {
		if j.urgent == nil {
			j.urgent = make(chan struct{}, 1)
		}
		slots = j.urgent
	}
	select {
	case slots <- struct{}{}:
	default:
		j.mu.Unlock()
		return errors.New("utility workers are busy")
	}
	child, cancel := context.WithCancel(ctx)
	j.running[id] = cancel
	j.mu.Unlock()
	j.send(protocol.New("command.accepted", id, 0, map[string]string{"command": command}), true)
	go func() {
		defer func() { <-slots; cancel() }()
		progress := func(data any) { j.send(protocol.New("command.progress", id, 0, data), false) }
		data, e := fn(child, progress)
		result := JobResult{ID: id, Command: command, Status: "completed", Data: data, Finished: time.Now().UTC()}
		if e != nil {
			result.Status = "failed"
			result.Error = "utility operation failed"
			if j.redact != nil {
				result.Error = j.redact(e.Error())
			}
		}
		if errors.Is(child.Err(), context.Canceled) {
			result.Status = "cancelled"
		}
		j.mu.Lock()
		delete(j.running, id)
		j.history = append(j.history, result)
		if len(j.history) > 128 {
			j.history = j.history[len(j.history)-128:]
		}
		b, _ := json.Marshal(durableJobHistory(j.history))
		persistErr := state.AtomicWrite(j.path, b, 0600)
		j.mu.Unlock()
		if persistErr != nil {
			result.Status = "failed"
			result.Error = "job result persistence failed"
		}
		j.send(protocol.New("command.result", id, 0, result), true)
	}()
	return nil
}
func (j *Jobs) Cancel(id string) bool {
	j.mu.Lock()
	cancel := j.running[id]
	j.mu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}
func (j *Jobs) Snapshot() []JobResult {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := protocol.Clone(j.history)
	for id := range j.running {
		out = append(out, JobResult{ID: id, Status: "running"})
	}
	return out
}
