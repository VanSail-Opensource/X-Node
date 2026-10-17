package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

type accountingRequest struct {
	ctx      context.Context
	quiesced bool
	period   string
	result   chan accountingResult
}
type accountingResult struct {
	barrier protocol.TrafficBarrier
	err     error
}

func (a *Agent) captureTraffic() error {
	a.Registry.SampleActivity()
	now := time.Now()
	from := a.lastCapture
	if from.IsZero() {
		from = now.Add(-time.Second)
	}
	elapsed := now.Sub(from).Seconds()
	if now.UTC().Before(from.UTC()) {
		from = now
	}
	current, delta := a.Registry.Counters(), state.Traffic{}
	for id, bytes := range current {
		old := a.previous[id]
		up, down := bytes[0], bytes[1]
		if bytes[0] >= old[0] {
			up -= old[0]
		}
		if bytes[1] >= old[1] {
			down -= old[1]
		}
		if up > 0 || down > 0 {
			delta[id] = [2]uint64{up, down}
		}
	}
	nextAccounting := map[string][2]uint64{}
	periodTotals := state.Traffic{}
	var samples []protocol.TrafficSample
	for _, counter := range a.Registry.AccountingCounters() {
		key := fmt.Sprintf("%d:%s", counter.UserID, counter.Period)
		old := a.previousAccounting[key]
		if counter.Upload < old[0] || counter.Download < old[1] {
			return errors.New("accounting counter regressed")
		}
		nextAccounting[key] = [2]uint64{counter.Upload, counter.Download}
		up, down := counter.Upload-old[0], counter.Download-old[1]
		if up == 0 && down == 0 {
			continue
		}
		totals := periodTotals[counter.UserID]
		if ^uint64(0)-totals[0] < up || ^uint64(0)-totals[1] < down {
			return errors.New("accounting counter overflow")
		}
		periodTotals[counter.UserID] = [2]uint64{totals[0] + up, totals[1] + down}
		samples = append(samples, protocol.TrafficSample{UserID: counter.UserID, AccountingPeriod: counter.Period, From: from.UTC(), Through: now.UTC(), UploadBytes: up, DownloadBytes: down})
	}
	for id, totals := range periodTotals {
		delta[id] = totals
	}
	if err := a.Store.AddAccounting(delta, samples); err != nil {
		return err
	}
	a.previous, a.previousAccounting, a.lastCapture = current, nextAccounting, now
	a.Registry.SetRates(delta, elapsed)
	a.Registry.PruneAccounting()
	a.Registry.PruneCounters()
	return nil
}

func (a *Agent) flushTraffic(ctx context.Context, raw []byte) (any, error) {
	var args protocol.TrafficFlush
	if err := protocol.Decode(raw, &args); err != nil {
		return nil, err
	}
	if args.UserID < 0 || args.AccountingPeriod != "" && (!args.Quiesce || args.UserID <= 0 || !protocol.ValidName(args.AccountingPeriod)) {
		return nil, errors.New("invalid traffic flush user")
	}
	child, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if args.Quiesce {
		var release func()
		var err error
		if args.AccountingPeriod != "" {
			release, err = a.Registry.QuiescePeriod(child, args.UserID, args.AccountingPeriod)
		} else {
			release, err = a.Registry.Quiesce(child, args.UserID)
		}
		if err != nil {
			return nil, err
		}
		defer release()
	}
	request := accountingRequest{ctx: child, quiesced: args.Quiesce, period: args.AccountingPeriod, result: make(chan accountingResult, 1)}
	select {
	case a.accountingRequests <- request:
	case <-child.Done():
		return nil, child.Err()
	}
	select {
	case result := <-request.result:
		return result.barrier, result.err
	case <-child.Done():
		return nil, child.Err()
	}
}

func (a *Agent) handleAccounting(request accountingRequest) {
	if request.ctx.Err() != nil {
		request.result <- accountingResult{err: request.ctx.Err()}
		return
	}
	if err := a.captureTraffic(); err != nil {
		a.failStorage(err)
		request.result <- accountingResult{err: err}
		return
	}
	barrier, err := a.Store.Flush()
	if err != nil {
		a.failStorage(err)
	}
	barrier.Quiesced = request.quiesced
	barrier.AccountingPeriod = request.period
	request.result <- accountingResult{barrier, err}
	a.lastReport = time.Time{}
}
