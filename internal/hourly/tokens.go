package hourly

import (
	"math/bits"
	"time"
)

func (b *bucket) capacity() uint64 {
	if b.grant == nil {
		return 0
	}
	burst := uint64(b.grant.grant.BurstBytes)
	if b.held >= burst {
		return 0
	}
	return burst - b.held
}

func (b *bucket) refill(now time.Time) {
	if !now.After(b.last) || b.grant == nil {
		return
	}
	elapsed := uint64(now.Sub(b.last))
	b.last = now
	rate, capacity := b.grant.grant.RateBytesPerSecond, b.capacity()
	if rate == 0 || b.tokens >= capacity {
		b.tokens = min(b.tokens, capacity)
		b.remainder = 0
		return
	}
	hi, lo := bits.Mul64(rate, elapsed)
	lo, carry := bits.Add64(lo, b.remainder, 0)
	hi += carry
	if hi >= uint64(time.Second) {
		b.tokens, b.remainder = capacity, 0
		return
	}
	add, remainder := bits.Div64(hi, lo, uint64(time.Second))
	if add >= capacity-b.tokens {
		b.tokens, b.remainder = capacity, 0
	} else {
		b.tokens += add
		b.remainder = remainder
	}
}

func (b *bucket) delay(bytes uint64) time.Duration {
	if b.grant == nil || b.grant.grant.RateBytesPerSecond == 0 {
		return 0
	}
	rate := b.grant.grant.RateBytesPerSecond
	// At most a native handoff's 16 KiB is requested here.
	nanos := bytes * uint64(time.Second)
	if nanos <= b.remainder {
		return time.Nanosecond
	}
	nanos -= b.remainder
	delay := nanos / rate
	if nanos%rate != 0 {
		delay++
	}
	return time.Duration(max(1, delay))
}
