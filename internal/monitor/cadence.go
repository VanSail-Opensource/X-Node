package monitor

import (
	"context"
	"time"
)

func (s *Sampler) Interval(d time.Duration) {
	d = max(time.Second, d)
	if s.interval.Swap(int64(d)) == int64(d) {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Ticks measure start-to-start cadence instead of sleeping after collection.
// There is one collector; missed ticks coalesce and never create a backlog.
func (s *Sampler) Run(ctx context.Context) {
	tick := time.NewTicker(time.Duration(s.interval.Load()))
	defer tick.Stop()
	s.sample(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			tick.Reset(time.Duration(s.interval.Load()))
		case <-tick.C:
			s.sample(ctx)
		}
	}
}

func (s *Sampler) sample(ctx context.Context) {
	child, cancel := context.WithTimeout(ctx, min(5*time.Second, time.Duration(s.interval.Load())))
	defer cancel()
	snapshot := s.collect(child, time.Now())
	s.latest.Store(&snapshot)
}
