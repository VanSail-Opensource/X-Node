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
	var traffic protocol.Message // immutable, report worker only
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
				if err := a.sendTrafficReport(&traffic, true); err != nil {
					a.failStorage(err)
				}
				entries, dropped := a.Logs.Drain()
				if len(entries) > 0 || dropped > 0 {
					a.Client.Send(protocol.New("logs.report", "", 0, map[string]any{"entries": entries, "dropped": dropped}), false)
				}
			} else if flags&reportReplay != 0 {
				// A replay never seals, so unlike the periodic operation it cannot
				// fail from queue pressure.
				_ = a.sendTrafficReport(&traffic, false)
			}
		}
	}
}

func (a *Agent) sendTrafficReport(cached *protocol.Message, seal bool) error {
	batch, unchanged, err := a.Store.TrafficReportHead(cached.ID, seal)
	if err != nil {
		return err
	}
	if !unchanged {
		*cached = protocol.Message{}
		if batch == nil {
			return nil
		}
		*cached = protocol.New("traffic.report", batch.ID, 0, batch)
	}
	// Negotiated compatibility is still checked by the socket writer on each
	// send. An unchanged report is replayed, not treated as acknowledged.
	a.Client.Send(*cached, true)
	return nil
}
