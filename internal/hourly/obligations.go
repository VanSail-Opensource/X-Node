package hourly

import (
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type creditState struct {
	owner     *ownerState
	installed InstalledCredit
	admitted  [2]uint64
	held      uint64
	frozen    bool
	sealDrain *Drain
}
type creditAllocation struct {
	credit *creditState
	bytes  uint64
}

func (s *creditState) available() uint64 {
	return s.installed.install.ByteCeiling - s.admitted[0] - s.admitted[1] - s.held
}

func (c *Controller) InstallCredit(installed InstalledCredit) error {
	spec := installed.install
	if protocol.ValidateHourlyInstall(spec) != nil || installed.marker == nil || installed.digest != protocol.HourlyInstallDigest(spec) {
		return ErrInvalid
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session == "" || spec.SessionID != c.session || spec.DayUTC != c.options.Now().UTC().Format(time.DateOnly) {
		return ErrRevoked
	}
	o := c.owners[OwnerKey{spec.Owner.ID, spec.Owner.Generation}]
	if o == nil {
		return ErrRevoked
	}
	eligible := false
	for key, authorization := range c.authorizations {
		if key.Owner == o.key && authorization.PaidThrough.After(c.options.Now()) {
			eligible = true
			break
		}
	}
	if !eligible {
		return ErrRevoked
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if old := o.credits[spec.ReservationID]; old != nil {
		if old.installed.digest != installed.digest {
			return ErrInvalid
		}
		return nil
	}
	if !reserveCount(&c.credits, creditJournalMaxObligations) {
		return ErrCapacity
	}
	credit := &creditState{owner: o, installed: installed}
	if _, exists := c.creditIndex.LoadOrStore(spec.ReservationID, credit); exists {
		c.credits.Add(-1)
		return ErrInvalid
	}
	if !installed.marker.claim() {
		c.creditIndex.Delete(spec.ReservationID)
		c.credits.Add(-1)
		return ErrRevoked
	}
	o.credits[spec.ReservationID] = credit
	o.creditLow = false
	o.signal()
	return nil
}

func (o *ownerState) creditAllocations(b *bucket, want uint64, session string) ([]creditAllocation, uint64) {
	keys := make([]string, 0, len(o.credits))
	for id, credit := range o.credits {
		i := credit.installed.install
		if !credit.frozen && i.SessionID == session && i.DayUTC == b.scope.DayUTC && credit.installed.marker.active() && credit.available() > 0 {
			keys = append(keys, id)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := o.credits[keys[i]].installed.install, o.credits[keys[j]].installed.install
		if a.Kind != b.Kind {
			return a.Kind == "free"
		}
		return a.IssueSequence < b.IssueSequence
	})
	var allocations []creditAllocation
	var allocated uint64
	for _, id := range keys {
		credit := o.credits[id]
		n := min(want-allocated, credit.available())
		if n > 0 {
			allocations = append(allocations, creditAllocation{credit, n})
			allocated += n
		}
		if allocated == want {
			break
		}
	}
	return allocations, allocated
}

// A low-water edge is a hint to redistribute existing credits, not authority to
// buy another block. The master proves actual exhaustion before any purchase.
func (o *ownerState) wakeLowCredit(b *bucket, session string) {
	var available, capacity uint64
	for _, credit := range o.credits {
		i := credit.installed.install
		if credit.frozen || i.SessionID != session || i.DayUTC != b.scope.DayUTC || !credit.installed.marker.active() {
			continue
		}
		capacity = saturatingAdd(capacity, i.ByteCeiling)
		available = saturatingAdd(available, credit.available())
	}
	low := available <= capacity/2
	if low && !o.creditLow {
		o.controller.notify()
	}
	o.creditLow = low
}

func saturatingAdd(a, b uint64) uint64 {
	if ^uint64(0)-a < b {
		return ^uint64(0)
	}
	return a + b
}
