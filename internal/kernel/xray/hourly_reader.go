package xray

import (
	"context"
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type hourlyReader struct {
	buf.Reader
	ctx      context.Context
	cancel   context.CancelFunc
	lease    *sessions.Lease
	acquire  hourlyAcquire
	datagram bool
	mu       sync.Mutex
	pending  buf.MultiBuffer
	terminal error
}

func (r *hourlyReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ctx.Err(); err != nil {
		return r.fail(err)
	}
	want, minimum, present := hourlyFront(&r.pending, r.datagram)
	if !present {
		if r.terminal != nil {
			return nil, r.terminal
		}
		r.pending, r.terminal = r.Reader.ReadMultiBuffer()
		if err := validateHourlyBuffers(r.pending, r.datagram); err != nil {
			return r.fail(err)
		}
		want, minimum, present = hourlyFront(&r.pending, r.datagram)
		if !present {
			return nil, r.terminal
		}
	}
	permit, err := acquireHourlyHandoff(r.ctx, r.acquire, hourly.Upload, want, minimum)
	if err != nil {
		return r.fail(err)
	}
	head := takeHourlyBuffer(&r.pending, permit.Bytes())
	if err = beginHourlyHandoff(r.ctx, permit); err != nil {
		permit.Complete(hourly.NotHandedOff)
		buf.ReleaseMulti(head)
		return r.fail(err)
	}
	if r.lease != nil {
		r.lease.Account(true, uint64(head.Len()))
	}
	permit.Complete(hourly.Accepted)
	if len(r.pending) == 0 {
		return head, r.terminal
	}
	return head, nil
}

func (r *hourlyReader) fail(err error) (buf.MultiBuffer, error) {
	buf.ReleaseMulti(r.pending)
	r.pending, r.terminal = nil, err
	return nil, err
}

func (r *hourlyReader) Interrupt() {
	r.cancel()
	_ = common.Interrupt(r.Reader)
	r.releasePending()
}

func (r *hourlyReader) releasePending() {
	r.mu.Lock()
	buf.ReleaseMulti(r.pending)
	r.pending = nil
	r.mu.Unlock()
}
