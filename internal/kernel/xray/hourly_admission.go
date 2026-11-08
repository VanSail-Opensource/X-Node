package xray

import (
	"context"
	"errors"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/xtls/xray-core/common/buf"
)

// A newer grant can cancel an unstarted ticket after reservation. Keep the
// exact native buffers until Begin succeeds; reacquisition rejects real fences.
func admitHourlyBuffer(ctx context.Context, acquire hourlyAcquire, direction hourly.Direction, pending *buf.MultiBuffer, datagram bool) (buf.MultiBuffer, hourlyHandoff, error) {
	for {
		want, minimum, present := hourlyFront(pending, datagram)
		if !present {
			return nil, nil, hourly.ErrInvalid
		}
		permit, err := acquireHourlyHandoff(ctx, acquire, direction, want, minimum)
		if err != nil {
			return nil, nil, err
		}
		head := takeHourlyBuffer(pending, permit.Bytes())
		if err = beginHourlyHandoff(ctx, permit); err == nil {
			return head, permit, nil
		}
		permit.Complete(hourly.NotHandedOff)
		*pending = append(head, (*pending)...)
		if !errors.Is(err, hourly.ErrRevoked) {
			return nil, nil, err
		}
	}
}
