package state

import (
	"errors"
	"math"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// Record advances the discovery snapshot only after its event is durable. A
// failed discovery never calls this method, preserving the last valid addresses.
func (j *DDNSJournal) Record(job protocol.DDNSJob, ipv4, ipv6 string, at time.Time, current []protocol.DDNSJob) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if job.Generation == "" {
		return nil
	}
	last := j.data.Last[job.ID]
	if last.Generation == job.Generation && last.IPv4 == ipv4 && last.IPv6 == ipv6 {
		return nil
	}
	if j.data.Sequence == math.MaxUint64 || len(j.data.Pending) >= maxDDNSJournalEntries {
		return errors.New("DDNS journal capacity exhausted")
	}
	event := protocol.DDNSChange{ID: ID(), JobID: job.ID, Generation: job.Generation, Sequence: j.data.Sequence + 1, IPv4: ipv4, IPv6: ipv6, ObservedAt: at.UTC()}
	if err := event.Validate(); err != nil {
		return err
	}
	next := protocol.Clone(j.data)
	active := map[string]bool{}
	for _, configured := range current {
		active[configured.ID] = true
	}
	for id := range next.Last {
		if !active[id] {
			delete(next.Last, id)
		}
	}
	if len(next.Last) >= maxDDNSJournalEntries && next.Last[job.ID].JobID == "" {
		return errors.New("DDNS snapshot capacity exhausted")
	}
	next.Sequence = event.Sequence
	next.Last[job.ID] = event
	next.Pending = append(next.Pending, event)
	return j.persist(next)
}
