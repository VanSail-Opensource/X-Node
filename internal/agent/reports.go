package agent

import (
	"context"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const (
	reportStatus uint32 = 1 << iota
	reportPeriodic
	reportReplay
)

// Requests coalesce into one bounded worker. Accounting capture stays actor-owned.
func (a *Agent) requestReports(flags uint32) {
	a.reportFlags.Or(flags)
	select {
	case a.reportWake <- struct{}{}:
	default:
	}
}

func (a *Agent) runReports(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.reportWake:
			if ctx.Err() != nil {
				return
			}
			flags := a.reportFlags.Swap(0)
			if flags&reportStatus != 0 {
				a.publishStatus()
			}
			if flags&reportPeriodic != 0 {
				if a.ddnsJournal != nil && a.Client.DDNSChanges() {
					if changes := a.ddnsJournal.Pending(); len(changes) > 0 {
						a.Client.Send(protocol.New("ddns.changes", "", 0, protocol.DDNSChanges{Changes: changes}), true)
					}
				}
				batch, err := a.Store.Batch()
				if err != nil {
					a.failStorage(err)
				} else if batch != nil {
					a.Client.Send(protocol.New("traffic.report", batch.ID, 0, batch), true)
				}
				entries, dropped := a.Logs.Drain()
				if len(entries) > 0 || dropped > 0 {
					a.Client.Send(protocol.New("logs.report", "", 0, map[string]any{"entries": entries, "dropped": dropped}), false)
				}
			} else if flags&reportReplay != 0 {
				if batch := a.Store.Pending(); batch != nil {
					a.Client.Send(protocol.New("traffic.report", batch.ID, 0, batch), true)
				}
			}
		}
	}
}
