package sessions

import (
	"context"
	"sync"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"golang.org/x/time/rate"
)

// Speed is aggregate uploaded plus downloaded payload across a user's sessions.
// One-second elapsed windows avoid deriving throughput from reporting intervals.
type speedPolicy struct {
	mu                    sync.Mutex
	hard, normal          *rate.Limiter
	normalMbps, burstMbps int
	after, reset          time.Duration
	start                 time.Time
	bytes                 int64
	above, below          time.Duration
	limited               bool
}
type SpeedStatus = protocol.UserSpeedStatus

func sameSpeed(a, b protocol.User) bool {
	return a.SpeedLimitMbps == b.SpeedLimitMbps && a.BurstSpeedLimitMbps == b.BurstSpeedLimitMbps && a.SpeedLimitAfterSeconds == b.SpeedLimitAfterSeconds && a.SpeedLimitResetSeconds == b.SpeedLimitResetSeconds
}
func newSpeedPolicy(u protocol.User) *speedPolicy {
	p := &speedPolicy{normalMbps: u.SpeedLimitMbps, burstMbps: u.BurstSpeedLimitMbps, after: time.Duration(u.SpeedLimitAfterSeconds) * time.Second, reset: time.Duration(u.SpeedLimitResetSeconds) * time.Second}
	if p.after == 0 {
		p.after = 10 * time.Second
	}
	if p.reset == 0 {
		p.reset = time.Second
	}
	if p.burstMbps == 0 {
		p.burstMbps = p.normalMbps
	}
	if p.burstMbps > 0 {
		p.hard = rate.NewLimiter(rate.Limit(float64(p.burstMbps)*1e6/8), 16<<10)
	}
	if p.normalMbps > 0 {
		p.normal = rate.NewLimiter(rate.Limit(float64(p.normalMbps)*1e6/8), 16<<10)
	}
	return p
}
func (p *speedPolicy) advance(now time.Time) {
	if p.start.IsZero() {
		p.start = now
		return
	}
	elapsed := now.Sub(p.start)
	if elapsed < time.Second {
		return
	}
	throughput := float64(p.bytes) / elapsed.Seconds()
	normal := float64(p.normalMbps) * 1e6 / 8
	if p.limited {
		if throughput < normal*0.9 {
			p.below += elapsed
		} else {
			p.below = 0
		}
		if p.below >= p.reset {
			p.limited = false
			p.above = 0
			p.below = 0
		}
	} else {
		if throughput > normal {
			p.above += elapsed
		} else {
			p.above = 0
		}
		if p.above >= p.after {
			p.limited = true
			p.below = 0
		}
	}
	p.start = now
	p.bytes = 0
}
func (p *speedPolicy) wait(ctx context.Context, n int) error {
	if p == nil || p.hard == nil {
		return nil
	}
	for n > 0 {
		chunk := min(n, p.hard.Burst())
		if e := p.hard.WaitN(ctx, chunk); e != nil {
			return e
		}
		p.mu.Lock()
		p.advance(time.Now())
		limited := p.limited
		p.mu.Unlock()
		if limited && p.burstMbps > p.normalMbps {
			if e := p.normal.WaitN(ctx, chunk); e != nil {
				return e
			}
		}
		p.mu.Lock()
		p.bytes += int64(chunk)
		p.mu.Unlock()
		n -= chunk
	}
	return nil
}
func (p *speedPolicy) status() SpeedStatus {
	if p == nil {
		return SpeedStatus{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	active := p.burstMbps
	if p.limited {
		active = p.normalMbps
	}
	return SpeedStatus{NormalMbps: p.normalMbps, BurstMbps: p.burstMbps, Limited: p.limited, ActiveMbps: active}
}
