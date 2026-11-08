package sessions

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func hourlyBinding(user protocol.User) hourly.BindingKey {
	return hourly.BindingKey{Owner: hourly.OwnerKey{ID: user.Hourly.Owner.ID, Generation: user.Hourly.Owner.Generation}, EnrollmentID: user.Hourly.EnrollmentID, PrincipalID: user.ID, PeriodID: user.AccountingPeriod}
}

func (l *Lease) captureHourly(user protocol.User, controller *hourly.Controller, sequence uint64, ready bool) {
	if !l.transit && user.Hourly != nil {
		binding := hourlyBinding(user)
		l.hourlyBinding, l.hourlyController = &binding, controller
		l.hourlySequence, l.hourlyReady = sequence, ready
	}
}

// AcquireTrackedWithHourlyFence adds a native transport interruption used only
// by controller fencing. Normal completion, legacy and transit never invoke it.
func (r *Registry) AcquireTrackedWithHourlyFence(ctx context.Context, id int, identity, tag, ip, destination, network string, port int, cancel, fence func()) (*Lease, error) {
	return r.acquireHourly(ctx, id, identity, tag, ip, destination, network, port, cancel, true, fence)
}

func (r *Registry) acquireHourly(ctx context.Context, id int, identity, tag, ip, destination, network string, port int, cancel func(), tracked bool, fence func()) (*Lease, error) {
	lease, err := r.acquire(ctx, id, identity, tag, ip, destination, network, port, cancel, tracked)
	if err != nil || lease.hourlyBinding == nil {
		return lease, err
	}
	if err = ctx.Err(); err == nil {
		if lease.hourlyController == nil || !lease.hourlyReady {
			err = hourly.ErrUnavailable
		} else {
			var flow *hourly.Flow
			interrupt := lease.Close
			if fence != nil {
				interrupt = func() { defer lease.Close(); fence() }
			}
			flow, err = lease.hourlyController.OpenFlow(*lease.hourlyBinding, interrupt)
			if err == nil {
				r.mu.RLock()
				current := r.hourly == lease.hourlyController && r.hourlySequence == lease.hourlySequence && r.hourlyApplied == lease.hourlySequence
				r.mu.RUnlock()
				lease.hourlyMu.Lock()
				if lease.hourlyClosed || !current {
					err = hourly.ErrRevoked
				} else {
					lease.hourlyFlow = flow
				}
				lease.hourlyMu.Unlock()
				if err != nil {
					flow.Close()
				}
			}
		}
	}
	if err != nil {
		lease.Close()
		lease.Finish()
		return nil, err
	}
	return lease, nil
}

// HourlyFlow distinguishes hourly admission from ordinary and transit leases.
// An hourly lease with an absent flow must never use legacy-only accounting.
func (l *Lease) HourlyFlow() (*hourly.Flow, bool) {
	l.hourlyMu.Lock()
	defer l.hourlyMu.Unlock()
	return l.hourlyFlow, l.hourlyBinding != nil
}

func (l *Lease) closeHourly() {
	l.hourlyMu.Lock()
	l.hourlyClosed = true
	flow := l.hourlyFlow
	l.hourlyMu.Unlock()
	if flow != nil {
		flow.Close()
	}
}
