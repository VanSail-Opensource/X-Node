package agent

import (
	"context"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) retireHourlyCredits(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var cursor uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !a.checkHourlyHealth() {
			continue
		}
		h := a.hourly
		h.creditMu.Lock()
		installs := make([]protocol.HourlyCreditInstall, 0, len(h.installed))
		for _, install := range h.installed {
			installs = append(installs, install)
		}
		h.creditMu.Unlock()
		sort.Slice(installs, func(i, j int) bool { return installs[i].ReservationID < installs[j].ReservationID })
		if len(installs) == 0 {
			continue
		}
		session, day := a.Client.HourlyAuthoritySession(), time.Now().UTC().Format(time.DateOnly)
		for n := 0; n < min(4, len(installs)); n++ {
			install := installs[(int(cursor%uint64(len(installs)))+n)%len(installs)]
			if ctx.Err() != nil {
				break
			}
			if session == install.SessionID && day == install.DayUTC {
				continue
			}
			sealCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			_, _ = h.sealCredit(sealCtx, install.ReservationID)
			cancel()
			if !h.store.Healthy() {
				break
			}
		}
		cursor += 4
		a.checkHourlyHealth()
	}
}
