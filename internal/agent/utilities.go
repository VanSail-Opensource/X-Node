package agent

import (
	"context"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net/http"
	"path/filepath"
	"time"
)

func (a *Agent) ensureAssets(ctx context.Context, c protocol.Config, p geodata.Policy, refresh bool) error {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var client *http.Client
	if p.Outbound != "" {
		proxy, close, e := xray.DownloadClient(ctx, c.Xray, p.Outbound)
		if e != nil {
			return e
		}
		defer close()
		client = proxy
	}
	return geodata.Ensure(ctx, filepath.Join(a.Dir, "geodata"), p, c.AssetHashes, client, refresh)
}
func (a *Agent) scheduleUtilities(ctx context.Context, now time.Time) {
	notifySystemd("WATCHDOG=1")
	if a.applying.Load() {
		return
	}
	if a.utilityContext != nil {
		ctx = a.utilityContext
	}
	c := protocol.Clone(a.desired)
	for _, job := range c.DDNS {
		interval := time.Duration(job.IntervalSeconds) * time.Second
		if interval == 0 {
			interval = 5 * time.Minute
		}
		if now.Sub(a.lastDDNS[job.ID]) < interval {
			continue
		}
		a.lastDDNS[job.ID] = now
		job := job
		p := c.Providers[job.Provider]
		_ = a.Jobs.Start(ctx, "internal-ddns-"+fmt.Sprint(now.UnixNano()), "ddns", func(ctx context.Context, progress func(any)) (any, error) {
			a.dnsMu.Lock()
			defer a.dnsMu.Unlock()
			child, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			provider, e := dns.Provider(p)
			if e != nil {
				return nil, e
			}
			return dns.DDNS(child, job, provider, nil)
		})
	}
	if next := a.geoNext.Load(); next > 0 && now.UnixNano() >= next && !a.geoRunning.Load() {
		p, e := geodata.FromNative(c.Xray)
		if e == nil {
			err := a.Jobs.Start(ctx, "internal-geo-"+fmt.Sprint(now.UnixNano()), "geodata.refresh", func(ctx context.Context, progress func(any)) (any, error) {
				if e := a.refreshGeodata(ctx, c, p); e != nil {
					return nil, e
				}
				select {
				case a.notify <- "geodata-refresh":
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				return map[string]bool{"refreshed": true}, nil
			})
			if err != nil {
				a.finishGeodata(p, err)
			}
		}
	}
	if now.Sub(a.lastUpdate) >= 24*time.Hour {
		a.lastUpdate = now
		_ = a.Jobs.Start(ctx, "internal-update-"+fmt.Sprint(now.UnixNano()), "update.check", func(ctx context.Context, progress func(any)) (any, error) {
			release, e := a.Updater.Check(ctx, c.Updates.Version)
			if e != nil {
				return nil, e
			}
			if c.Updates.Enabled && release.Available {
				return a.Updater.Install(ctx, "internal-update", release.Version, progress)
			}
			return release, nil
		})
	}
}
