package hourly

import (
	"math"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type sampleKey struct {
	binding BindingKey
	day     string
}
type sampleCounter struct{ sample protocol.HourlySample }

func (o *ownerState) recordSample(p *Permit, now time.Time) error {
	if p.bytes == 0 {
		return nil
	}
	key := sampleKey{p.flow.binding, p.bucket.scope.DayUTC}
	counter := o.samples[key]
	if counter == nil {
		if !reserveCount(&o.controller.samples, o.controller.options.MaxFlows) {
			return ErrCapacity
		}
		generation := o.controller.nextCounterGeneration()
		if generation == 0 {
			o.controller.samples.Add(-1)
			return ErrCapacity
		}
		b := key.binding
		counter = &sampleCounter{protocol.HourlySample{Owner: protocol.HourlyOwner{ID: b.Owner.ID, Generation: b.Owner.Generation}, EnrollmentID: b.EnrollmentID, UserID: b.PrincipalID, AccountingPeriod: b.PeriodID, DayUTC: key.day, CounterGeneration: generation, From: now.UTC(), Through: now.UTC()}}
		o.samples[key] = counter
	}
	sample := &counter.sample
	if uint64(p.bytes) > math.MaxInt64-sample.UploadBytes-sample.DownloadBytes {
		return ErrCapacity
	}
	if p.direction == Upload {
		sample.UploadBytes += uint64(p.bytes)
	} else {
		sample.DownloadBytes += uint64(p.bytes)
	}
	if now.After(sample.Through) {
		sample.Through = now.UTC()
	}
	return nil
}

func (c *Controller) nextCounterGeneration() uint64 {
	for {
		previous := c.counterSequence.Load()
		if previous == ^uint64(0) {
			return 0
		}
		if c.counterSequence.CompareAndSwap(previous, previous+1) {
			return previous + 1
		}
	}
}

func (c *Controller) Samples() []protocol.HourlySample {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var result []protocol.HourlySample
	for _, owner := range c.owners {
		owner.mu.Lock()
		for _, counter := range owner.samples {
			result = append(result, counter.sample)
		}
		owner.mu.Unlock()
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CounterGeneration < result[j].CounterGeneration })
	return result
}

// Call only after an immutable sample copy entered the accepted traffic journal.
func (c *Controller) PruneSamples(captured []protocol.HourlySample) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	day := c.options.Now().UTC().Format(time.DateOnly)
	for _, sample := range captured {
		owner := c.owners[OwnerKey{sample.Owner.ID, sample.Owner.Generation}]
		if owner == nil {
			continue
		}
		key := sampleKey{BindingKey{Owner: owner.key, EnrollmentID: sample.EnrollmentID, PeriodID: sample.AccountingPeriod, PrincipalID: sample.UserID}, sample.DayUTC}
		owner.mu.Lock()
		current := owner.samples[key]
		_, authorized := c.authorizations[key.binding]
		if current != nil && current.sample == sample && (!authorized || key.day != day) {
			delete(owner.samples, key)
			c.samples.Add(-1)
		}
		owner.mu.Unlock()
	}
}
