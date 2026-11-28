package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) ensureAssets(ctx context.Context, c protocol.Config, p geodata.Policy, refresh bool) (string, error) {
	a.geoMu.Lock()
	defer a.geoMu.Unlock()
	return prepareAssets(ctx, filepath.Join(a.Dir, "geodata"), c, p, refresh)
}

func prepareAssets(ctx context.Context, dir string, c protocol.Config, p geodata.Policy, refresh bool) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	// Laziness avoids constructing an unused core, not validating its selector.
	if p.Outbound != "" {
		var native struct {
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(c.Xray, &native); err != nil {
			return "", err
		}
		found := false
		for _, out := range native.Outbounds {
			found = found || out.Tag == p.Outbound
		}
		if !found {
			return "", errors.New("unknown asset download outbound")
		}
	}
	client, closeClient := lazyAssetClient(ctx, c, p)
	defer closeClient()
	return geodata.Prepare(ctx, dir, p, c.AssetHashes, client, refresh)
}
func (a *Agent) scheduleUtilities(ctx context.Context, now time.Time) {
	notifySystemd("WATCHDOG=1")
	if a.applying.Load() {
		return
	}
	if a.utilityContext != nil {
		ctx = a.utilityContext
	}
	// The actor owns desired. Inspect it directly and detach only the inputs
	// needed by due jobs that outlive this tick.
	var ddnsJobs []protocol.DDNSJob
	for _, job := range a.desired.DDNS {
		interval := time.Duration(job.IntervalSeconds) * time.Second
		if interval == 0 {
			interval = 5 * time.Minute
		}
		if now.Sub(a.lastDDNS[job.ID]) < interval {
			continue
		}
		// Only due jobs should move their captured input off the stack.
		job := job
		var c protocol.Config
		if job.Generation != "" {
			if ddnsJobs == nil {
				ddnsJobs = slices.Clone(a.desired.DDNS)
			}
			c.DDNS = ddnsJobs
		}
		if job.Provider != protocol.BuiltinDDNSProvider {
			provider := a.desired.Providers[job.Provider]
			provider.Credentials = maps.Clone(provider.Credentials)
			c.Providers = map[string]protocol.Provider{job.Provider: provider}
		}
		id := fmt.Sprintf("internal-ddns-%x-%d", sha256.Sum256([]byte(job.ID)), now.UnixNano())
		if err := a.Jobs.Start(ctx, id, "ddns.run", func(ctx context.Context, progress func(any)) (any, error) {
			return a.runDDNS(ctx, c, job)
		}); err == nil {
			a.lastDDNS[job.ID] = now
		}
	}
	if next := a.geoNext.Load(); next > 0 && now.UnixNano() >= next && !a.geoRunning.Load() {
		p, e := geodata.FromNative(a.desired.Xray)
		if e == nil {
			c := protocol.Config{Xray: bytes.Clone(a.desired.Xray)}
			if len(a.desired.AssetHashes) > 0 {
				// Match the accepted configuration's omitempty normalization.
				c.AssetHashes = maps.Clone(a.desired.AssetHashes)
			}
			err := a.Jobs.Start(ctx, "internal-geo-"+fmt.Sprint(now.UnixNano()), "geodata.refresh", func(ctx context.Context, progress func(any)) (any, error) {
				if e := a.refreshGeodata(ctx, c, p); e != nil {
					return nil, e
				}
				return a.reloadRuntime(ctx, "geodata-refresh")
			})
			if err != nil {
				a.finishGeodata(p, err)
			}
		}
	}
	if now.Sub(a.lastUpdate) >= 24*time.Hour {
		policy := a.desired.Updates
		if err := a.Jobs.Start(ctx, "internal-update-"+fmt.Sprint(now.UnixNano()), "update.check", func(ctx context.Context, progress func(any)) (any, error) {
			release, e := a.Updater.Check(ctx, policy.Version)
			if e != nil {
				return nil, e
			}
			if policy.Enabled && release.Available {
				return a.Updater.Install(ctx, "internal-update", release.Version, progress)
			}
			return release, nil
		}); err == nil {
			a.lastUpdate = now
		}
	}
}
