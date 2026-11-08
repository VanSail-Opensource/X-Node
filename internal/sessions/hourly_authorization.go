package sessions

import "github.com/VanSail-Opensource/X-Node/internal/hourly"

type hourlyPublication struct {
	registry           *Registry
	controller         *hourly.Controller
	sequence, revision uint64
	authorizations     []hourly.Authorization
}

// SetHourlyController installs the fail-closed ingress controller. Publishing and
// interrupting old flows happens outside the registry admission lock.
func (r *Registry) SetHourlyController(controller *hourly.Controller) {
	r.mu.Lock()
	old := r.hourly
	r.hourly = controller
	publication := r.hourlyPublication()
	var close []*Lease
	if old != controller {
		for _, lease := range r.connections {
			if lease.hourlyBinding != nil {
				close = append(close, lease)
			}
		}
	}
	r.mu.Unlock()
	publication.apply()
	for _, lease := range close {
		lease.Close()
	}
}

// hourlyPublication requires r.mu. Its immutable snapshot is applied after unlock.
func (r *Registry) hourlyPublication() hourlyPublication {
	r.hourlySequence++
	p := hourlyPublication{registry: r, controller: r.hourly, sequence: r.hourlySequence, revision: r.authorizationRevision}
	for _, user := range r.users {
		if user.policy.Hourly != nil && user.policy.ValidUntil != nil && len(user.policy.InboundTags) > 0 {
			p.authorizations = append(p.authorizations, hourly.Authorization{Key: hourlyBinding(user.policy), PaidThrough: *user.policy.ValidUntil})
		}
	}
	return p
}

func (p hourlyPublication) apply() {
	accepted := p.controller != nil && p.controller.ApplyAuthorization(p.sequence, p.revision, p.authorizations)
	r := p.registry
	r.mu.Lock()
	var close []*Lease
	if r.hourly == p.controller && r.hourlySequence == p.sequence && r.hourlyApplied != p.sequence {
		r.hourlyApplied = 0
		if accepted {
			r.hourlyApplied = p.sequence
		} else {
			for _, lease := range r.connections {
				if lease.hourlyBinding != nil {
					close = append(close, lease)
				}
			}
		}
	}
	r.mu.Unlock()
	for _, lease := range close {
		lease.Close()
	}
}
