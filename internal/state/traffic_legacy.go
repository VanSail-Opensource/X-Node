package state

import (
	"errors"
	"fmt"
	"sort"
)

// Only upgrade recovery seals existing persisted accumulation. New captures never
// enter Data. Existing pending/backlog identities and values remain unchanged.
func sealLegacyTraffic(d *Data) error {
	if len(d.Accumulated) == 0 && len(d.Accounting) == 0 {
		return nil
	}
	if d.Sequence == ^uint64(0) {
		return errors.New("traffic sequence exhausted")
	}
	d.Sequence++
	batch := &Batch{ID: fmt.Sprintf("%s:%d", d.AgentID, d.Sequence), Traffic: d.Accumulated}
	keys := make([]string, 0, len(d.Accounting))
	for key := range d.Accounting {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		batch.Samples = append(batch.Samples, d.Accounting[key])
	}
	d.Accumulated = Traffic{}
	d.Accounting = nil
	if d.Pending == nil {
		d.Pending = batch
	} else {
		d.Backlog = append(d.Backlog, batch)
	}
	return nil
}
