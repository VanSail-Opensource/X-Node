package hourly

import (
	"sort"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (c *Controller) CreditProgress(limit int) []protocol.HourlyCreditProgress {
	limit = min(max(limit, 0), protocol.MaxHourlyItems)
	var credits []*creditState
	c.creditIndex.Range(func(_, value any) bool { credits = append(credits, value.(*creditState)); return true })
	sort.Slice(credits, func(i, j int) bool {
		return credits[i].installed.install.ReservationID < credits[j].installed.install.ReservationID
	})
	if len(credits) == 0 || limit == 0 {
		return nil
	}
	start := int(c.progressCursor.Add(uint64(limit))-uint64(limit)) % len(credits)
	var result []protocol.HourlyCreditProgress
	for n := 0; n < len(credits) && len(result) < limit; n++ {
		credit := credits[(start+n)%len(credits)]
		credit.owner.mu.Lock()
		i := credit.installed.install
		result = append(result, protocol.HourlyCreditProgress{ReservationID: i.ReservationID, IssueSequence: i.IssueSequence, AdmittedUploadBytes: credit.admitted[0], AdmittedDownloadBytes: credit.admitted[1]})
		credit.owner.mu.Unlock()
	}
	return result
}

func (c *Controller) FreezeCredit(id string) (*Drain, error) {
	value, ok := c.creditIndex.Load(id)
	if !ok {
		return nil, ErrInvalid
	}
	credit := value.(*creditState)
	o := credit.owner
	o.mu.Lock()
	if credit.sealDrain != nil {
		drain := credit.sealDrain
		o.mu.Unlock()
		return drain, nil
	}
	credit.frozen = true
	drain := newDrain()
	credit.sealDrain = drain
	drain.owner, drain.credit = o, credit
	actions := o.fence(func(p *Permit) bool {
		for _, a := range p.credits {
			if a.credit == credit {
				return true
			}
		}
		return false
	}, id, drain)
	o.signal()
	o.mu.Unlock()
	drain.finishAdmission()
	runFences(actions)
	return drain, nil
}

func (c *Controller) PrepareSeal(drain *Drain) (SealCandidate, error) {
	if drain == nil || drain.credit == nil || drain.owner.controller != c {
		return SealCandidate{}, ErrInvalid
	}
	select {
	case <-drain.Done():
	default:
		return SealCandidate{}, ErrUnavailable
	}
	o, credit := drain.owner, drain.credit
	o.mu.Lock()
	defer o.mu.Unlock()
	if !credit.frozen || credit.held != 0 {
		return SealCandidate{}, ErrUnavailable
	}
	return SealCandidate{credit: credit.installed, admitted: credit.admitted, unused: credit.available()}, nil
}
