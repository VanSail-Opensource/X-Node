package hourly

import "sync"

type Drain struct {
	mu      sync.Mutex
	done    chan struct{}
	pending int
	owner   *ownerState
	credit  *creditState
}

func newDrain() *Drain                 { return &Drain{done: make(chan struct{}), pending: 1} }
func completedDrain() *Drain           { d := newDrain(); d.finishAdmission(); return d }
func (d *Drain) Done() <-chan struct{} { return d.done }
func (d *Drain) add()                  { d.mu.Lock(); d.pending++; d.mu.Unlock() }
func (d *Drain) finishAdmission() {
	d.mu.Lock()
	d.pending--
	if d.pending == 0 {
		close(d.done)
	}
	d.mu.Unlock()
}

type fenceAction struct {
	flow  *Flow
	drain *Drain
}

func runFences(actions []fenceAction) {
	for _, action := range actions {
		func() { defer action.drain.finishAdmission(); action.flow.interrupt() }()
	}
}

// Matching a handoff fences its complete native flow, including the opposite
// direction. The hook may close the flow recursively, so invoke it after unlock.
func (o *ownerState) fence(match func(*Permit) bool, _ string, drain *Drain) []fenceAction {
	flows := map[*Flow]bool{}
	for permit := range o.permits {
		if match(permit) {
			flows[permit.flow] = true
		}
	}
	return o.fenceFlows(func(flow *Flow) bool { return flows[flow] }, drain)
}

func (o *ownerState) fenceFlows(match func(*Flow) bool, drain *Drain) []fenceAction {
	local := drain == nil
	if local {
		drain = newDrain()
	}
	var actions []fenceAction
	flows := map[*Flow]bool{}
	for flow := range o.flows {
		flows[flow] = true
	}
	for permit := range o.permits {
		flows[permit.flow] = true
	}
	for flow := range flows {
		if !match(flow) {
			continue
		}
		flow.pending = [2]int{}
		for permit := range o.permits {
			if permit.flow != flow {
				continue
			}
			if !permit.started {
				permit.cancelLocked()
				continue
			}
			permit.drains = append(permit.drains, drain)
			drain.add()
		}
		if !flow.fenced && !flow.closed {
			flow.fenced = true
			drain.add()
			actions = append(actions, fenceAction{flow, drain})
		}
	}
	if local {
		drain.finishAdmission()
	}
	return actions
}
