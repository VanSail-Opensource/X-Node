package xray

import (
	"context"
	"sync"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type hourlyWriter struct {
	buf.Writer
	ctx      context.Context
	cancel   context.CancelFunc
	lease    *sessions.Lease
	acquire  hourlyAcquire
	datagram bool
	mu       sync.Mutex
}

func (w *hourlyWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Once handed to the underlying writer, buffers belong to it even on error.
	// Only this still-unhanded tail is ours to release.
	defer func() { buf.ReleaseMulti(mb) }()
	if err := validateHourlyBuffers(mb, w.datagram); err != nil {
		return err
	}
	for {
		want, minimum, present := hourlyFront(&mb, w.datagram)
		if !present {
			return nil
		}
		permit, err := acquireHourlyHandoff(w.ctx, w.acquire, hourly.Download, want, minimum)
		if err != nil {
			return err
		}
		head := takeHourlyBuffer(&mb, permit.Bytes())
		if err = beginHourlyHandoff(w.ctx, permit); err != nil {
			permit.Complete(hourly.NotHandedOff)
			buf.ReleaseMulti(head)
			return err
		}
		err = w.Writer.WriteMultiBuffer(head)
		outcome := hourly.Accepted
		if err != nil {
			outcome = hourly.Uncertain
		}
		permit.Complete(outcome)
		if err != nil {
			return err
		}
		if w.lease != nil {
			w.lease.Account(false, uint64(permit.Bytes()))
		}
	}
}

func (w *hourlyWriter) Close() error { return common.Close(w.Writer) }

func (w *hourlyWriter) Interrupt() {
	w.cancel()
	_ = common.Interrupt(w.Writer)
}
