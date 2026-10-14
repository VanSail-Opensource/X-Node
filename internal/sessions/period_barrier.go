package sessions

import (
	"context"
	"errors"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"time"
)

// QuiescePeriod finishes only an old accounting period. The member's new term
// remains admitted, so reconnecting journals cannot interrupt renewed access.
func (r *Registry) QuiescePeriod(ctx context.Context, id int, period string) (func(), error) {
	if id <= 0 || !protocol.ValidName(period) {
		return nil, errors.New("invalid accounting period barrier")
	}
	r.mu.Lock()
	if user := r.users[id]; user != nil && user.policy.AccountingPeriod == period && len(user.policy.InboundTags) > 0 && !user.policy.BlockNew && (user.policy.ValidUntil == nil || user.policy.ValidUntil.After(time.Now())) {
		r.mu.Unlock()
		return nil, errors.New("accounting period still admits traffic")
	}
	if r.periodFences == nil {
		r.periodFences = map[accountingKey]int{}
	}
	key := accountingKey{id, period}
	r.periodFences[key]++
	var tracked []*Lease
	for _, lease := range r.inflight {
		if lease.Info.UserID == id && lease.accountingPeriod == period {
			tracked = append(tracked, lease)
		}
	}
	r.mu.Unlock()
	release := func() {
		r.mu.Lock()
		r.periodFences[key]--
		if r.periodFences[key] == 0 {
			delete(r.periodFences, key)
		}
		r.mu.Unlock()
	}
	for _, lease := range tracked {
		lease.Close()
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
