package state

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const maxDDNSJournalBytes = 1 << 20
const maxDDNSJournalEntries = 1024

type ddnsData struct {
	Sequence uint64                         `json:"sequence"`
	Last     map[string]protocol.DDNSChange `json:"last"`
	Pending  []protocol.DDNSChange          `json:"pending"`
}

// A separate private file preserves DDNS ordering across a rollback to an older
// agent, which may rewrite state.json without understanding these fields.
type DDNSJournal struct {
	mu   sync.Mutex
	path string
	data ddnsData
}

func OpenDDNS(dir string) (*DDNSJournal, error) {
	j := &DDNSJournal{path: filepath.Join(dir, "ddns.json"), data: ddnsData{Last: map[string]protocol.DDNSChange{}}}
	file, err := os.Open(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxDDNSJournalBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDDNSJournalBytes || json.Unmarshal(raw, &j.data) != nil || len(j.data.Last) > maxDDNSJournalEntries || len(j.data.Pending) > maxDDNSJournalEntries {
		return nil, errors.New("invalid DDNS journal")
	}
	seen := map[string]bool{}
	var previous uint64
	for _, event := range j.data.Pending {
		if event.Validate() != nil || event.Sequence > j.data.Sequence || event.Sequence <= previous || seen[event.ID] {
			return nil, errors.New("invalid DDNS journal event")
		}
		seen[event.ID] = true
		previous = event.Sequence
	}
	if j.data.Last == nil {
		j.data.Last = map[string]protocol.DDNSChange{}
	}
	for job, event := range j.data.Last {
		if event.Validate() != nil || job != event.JobID || event.Sequence > j.data.Sequence {
			return nil, errors.New("invalid DDNS journal snapshot")
		}
	}
	return j, nil
}

func (j *DDNSJournal) persist(next ddnsData) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(raw) > maxDDNSJournalBytes {
		return errors.New("DDNS journal capacity exhausted")
	}
	if err = AtomicWrite(j.path, raw, 0600); err != nil {
		return err
	}
	j.data = next
	return nil
}

func (j *DDNSJournal) Pending() []protocol.DDNSChange {
	j.mu.Lock()
	defer j.mu.Unlock()
	end := min(len(j.data.Pending), protocol.MaxDDNSChangesPerFrame)
	return protocol.Clone(j.data.Pending[:end])
}

func (j *DDNSJournal) Acknowledge(ids []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(ids) > protocol.MaxDDNSChangesPerFrame {
		return errors.New("invalid DDNS acknowledgment")
	}
	set := map[string]bool{}
	for _, id := range ids {
		if !protocol.ValidName(id) {
			return errors.New("invalid DDNS acknowledgment")
		}
		set[id] = true
	}
	next := protocol.Clone(j.data)
	next.Pending = nil
	for _, event := range j.data.Pending {
		if !set[event.ID] {
			next.Pending = append(next.Pending, event)
		}
	}
	if len(next.Pending) == len(j.data.Pending) {
		return nil
	}
	return j.persist(next)
}
