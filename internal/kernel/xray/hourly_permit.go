package xray

import (
	"context"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
)

type hourlyHandoff interface {
	Bytes() int
	Begin() error
	Complete(hourly.Outcome)
}

type hourlyAcquire func(context.Context, hourly.Direction, int, int) (hourlyHandoff, error)

func acquireHourlyHandoff(ctx context.Context, acquire hourlyAcquire, direction hourly.Direction, want, minimum int) (hourlyHandoff, error) {
	permit, err := acquire(ctx, direction, want, minimum)
	if err != nil {
		return nil, err
	}
	if permit == nil {
		return nil, hourly.ErrUnavailable
	}
	if permit.Bytes() < minimum || permit.Bytes() > want || permit.Bytes() < 0 {
		permit.Complete(hourly.NotHandedOff)
		return nil, hourly.ErrInvalid
	}
	return permit, nil
}

func beginHourlyHandoff(ctx context.Context, permit hourlyHandoff) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return permit.Begin()
}

func hourlyAcquirer(flow *hourly.Flow) hourlyAcquire {
	return func(ctx context.Context, direction hourly.Direction, want, minimum int) (hourlyHandoff, error) {
		if flow == nil {
			return nil, hourly.ErrUnavailable
		}
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			permit, wait, err := flow.TryAcquire(direction, want, minimum)
			if err != nil || permit != nil {
				return permit, err
			}
			if err = waitHourly(ctx, wait); err != nil {
				return nil, err
			}
		}
	}
}

func waitHourly(ctx context.Context, wait hourly.Wait) error {
	var timer *time.Timer
	var elapsed <-chan time.Time
	if wait.After > 0 {
		timer = time.NewTimer(wait.After)
		elapsed = timer.C
		defer timer.Stop()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wait.Changed:
		return nil
	case <-elapsed:
		return nil
	}
}
