package sessions

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type accountingKey struct {
	user   int
	period string
}
type accountingCounters struct {
	upload, download atomic.Uint64
	leases           int
}
type AccountingCounter struct {
	UserID           int
	Period           string
	Upload, Download uint64
}

func (r *Registry) Acquire(ctx context.Context, id int, identity, tag, ip, destination, network string, port int, cancel func()) (*Lease, error) {
	return r.acquire(ctx, id, identity, tag, ip, destination, network, port, cancel, false)
}

// AcquireTracked keeps a separate completion barrier after admission slots are released.
func (r *Registry) AcquireTracked(ctx context.Context, id int, identity, tag, ip, destination, network string, port int, cancel func()) (*Lease, error) {
	return r.acquire(ctx, id, identity, tag, ip, destination, network, port, cancel, true)
}

func (r *Registry) initializeAccounting(lease *Lease, tracked bool) {
	lease.accountingPeriod = lease.user.policy.AccountingPeriod
	lease.tracked, lease.finished = tracked, make(chan struct{})
	if r.inflight == nil {
		r.inflight = map[string]*Lease{}
	}
	if tracked {
		r.inflight[lease.Info.ID] = lease
		lease.user.handlers++
	}
	if lease.user.policy.AccountingPeriod == "" {
		return
	}
	if r.accounting == nil {
		r.accounting = map[accountingKey]*accountingCounters{}
	}
	key := accountingKey{lease.Info.UserID, lease.user.policy.AccountingPeriod}
	counter := r.accounting[key]
	if counter == nil {
		counter = &accountingCounters{}
		r.accounting[key] = counter
	}
	counter.leases++
	lease.accounting = counter
}

// Finish is called when the native outbound handler has completed all payload copying.
func (l *Lease) Finish() {
	l.finishOnce.Do(func() {
		l.registry.mu.Lock()
		delete(l.registry.inflight, l.Info.ID)
		l.nativeFinished = true
		l.releaseResource()
		if l.tracked {
			l.user.handlers--
		}
		if l.accounting != nil {
			l.accounting.leases--
		}
		l.registry.mu.Unlock()
		close(l.finished)
	})
}

// AccountingCounters keeps old-period counters reachable until their leases and sampler finish.
func (r *Registry) AccountingCounters() []AccountingCounter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AccountingCounter, 0, len(r.accounting))
	for key, value := range r.accounting {
		out = append(out, AccountingCounter{key.user, key.period, value.upload.Load(), value.download.Load()})
	}
	return out
}

func (r *Registry) PruneAccounting() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, value := range r.accounting {
		u := r.users[key.user]
		if value.leases == 0 && (u == nil || u.policy.AccountingPeriod != key.period || len(u.policy.InboundTags) == 0) {
			delete(r.accounting, key)
		}
	}
}

func (r *Registry) SetRates(delta protocol.Traffic, elapsed float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rates = nil
	if elapsed <= 0 {
		return
	}
	for id, user := range r.users {
		if user.policy.AccountingPeriod == "" {
			continue
		}
		if r.rates == nil {
			r.rates = map[int]protocol.UserRate{}
		}
		r.rates[id] = protocol.UserRate{UploadBytesPerSecond: float64(delta[id][0]) / elapsed, DownloadBytesPerSecond: float64(delta[id][1]) / elapsed, SampleSeconds: elapsed}
	}
}

func (r *Registry) ExpireUsers(now time.Time) {
	r.mu.RLock()
	var expired []int
	for id, user := range r.users {
		if user.policy.ValidUntil != nil && !user.policy.ValidUntil.After(now) {
			expired = append(expired, id)
		}
	}
	r.mu.RUnlock()
	for _, id := range expired {
		r.CloseUser(id, "")
	}
}

// Quiesce requires an admission fence, closes streams, and waits for their native handlers.
// The returned release function must run after the actor seals its traffic barrier.
func (r *Registry) Quiesce(ctx context.Context, id int) (func(), error) {
	r.mu.Lock()
	for userID, user := range r.users {
		if id != 0 && userID != id {
			continue
		}
		if len(user.policy.InboundTags) > 0 && !user.policy.BlockNew && (user.policy.ValidUntil == nil || user.policy.ValidUntil.After(time.Now())) {
			r.mu.Unlock()
			return nil, errors.New("traffic quiescence requires blocked admission")
		}
	}
	if r.fences == nil {
		r.fences = map[int]int{}
	}
	r.fences[id]++
	var tracked []*Lease
	for _, lease := range r.inflight {
		if id == 0 || lease.Info.UserID == id {
			tracked = append(tracked, lease)
		}
	}
	r.mu.Unlock()
	release := func() {
		r.mu.Lock()
		r.fences[id]--
		if r.fences[id] == 0 {
			delete(r.fences, id)
		}
		r.mu.Unlock()
	}
	if id == 0 {
		r.CloseAll()
	} else {
		r.CloseUser(id, "")
	}
	for _, lease := range tracked {
		select {
		case <-lease.finished:
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		}
	}
	return release, nil
}
