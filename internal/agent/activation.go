package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// activate owns preparation, native commit and auxiliary reconciliation. It
// runs outside the actor, so disk/network work never holds traffic ACK handling.
func (a *Agent) activate(lifetime context.Context, job applyJob) error {
	a.nativeMu.Lock()
	defer a.nativeMu.Unlock()
	if err := job.Context.Err(); err != nil {
		return err
	}
	started := time.Now()
	c := protocol.Clone(job.Config)
	p, err := geodata.FromNative(c.Xray)
	if err != nil {
		return err
	}
	previous, hasPrevious := a.Store.Configuration()
	changes := protocol.Classify(previous, c)
	native := !hasPrevious || changes.Native || job.Reload || job.RefreshAssets || !a.Runtime.Ready()
	// A completed certificate renewal must recheck material even when the
	// desired document is unchanged; regular reconciliations avoid that I/O.
	native = native || job.RecheckMaterial
	assetDir := ""
	if native {
		if job.RefreshAssets {
			target, err := a.ensureAssets(job.Context, c, p, true)
			if err != nil {
				return err
			}
			a.geoCandidate, a.geoCandidateKey = target, assetKey(c, p)
		}
		candidate, dir, err := a.prepareNative(job.Context, lifetime, c, p, job.Reload)
		if err != nil {
			return err
		}
		assetDir = dir
		if err = a.stage(job, c); err != nil {
			return err
		}
		if err = a.Runtime.ApplyPrepared(lifetime, candidate, job.Reload); err != nil {
			return err
		}
		a.Certificates.RetainRuntime(c)
	} else {
		if err = a.stage(job, c); err != nil {
			return err
		}
		if !a.Runtime.Overlay(c) {
			return errors.New("runtime became unavailable")
		}
	}
	if err = job.Context.Err(); err != nil {
		return err
	}
	a.Sampler.Interval(c.SampleInterval())
	a.scheduleGeodata(p)
	if err = a.activateFirewall(job, c); err != nil {
		return err
	}
	a.Guard.Configure(c.Firewall)
	if assetDir != "" && len(p.Assets) > 0 {
		if err = geodata.Activate(filepath.Join(a.Dir, "geodata"), assetDir); err != nil {
			return err
		}
	}
	if err = a.Store.Accept(c, job.Revision); err != nil {
		return err
	}
	// Keep the verified immutable generation available to account/rule edits;
	// explicit validation/reload and scheduled refresh still recheck its bytes.
	if native {
		a.Certificates.Commit(c)
	}
	if err = a.Updater.Confirm(job.Context); err != nil {
		return err
	}
	a.Registry.Pause(false)
	a.systemdReady()
	stats := a.Runtime.Statistics()
	nlog.Core().Info("configuration applied", "revision", job.Revision, "mode", stats.LastMode,
		"prepare_apply_ms", time.Since(started).Milliseconds(), "native_builds", stats.NativeBuilds,
		"inbound_builds", stats.InboundBuilds, "outbound_builds", stats.OutboundBuilds,
		"routing_builds", stats.RoutingBuilds, "matcher_builds", stats.MatcherBuilds,
		"runtime_rebuilds", stats.Rebuilds, "listener_gap_ms", stats.ListenerGapMillis, "listener_gap_us", stats.ListenerGapMicros)
	return nil
}

func (a *Agent) stage(job applyJob, c protocol.Config) error {
	if err := job.Context.Err(); err != nil {
		return err
	}
	if a.Store.Revision() != job.Revision {
		return errors.New("configuration superseded")
	}
	if !job.Cached {
		return a.Store.Stage(c, job.Revision)
	}
	return nil
}

func (a *Agent) activateFirewall(job applyJob, c protocol.Config) error {
	if !c.Firewall.Enabled {
		if a.firewallInitialized {
			previous, ok := a.Store.Configuration()
			if ok && !previous.Firewall.Enabled {
				return nil
			}
		}
		if err := a.Firewall.RestoreOriginal(job.Context); err != nil {
			return err
		}
		a.firewallInitialized = true
		return nil
	}
	pending, reused, err := a.Firewall.Reuse(job.Context, c.Firewall, c.DNS.Redirect)
	if err != nil {
		return err
	}
	if !reused {
		if err = a.Firewall.EnableConfirmedDNS(job.Context, false); err != nil {
			return err
		}
		if job.Cached {
			if err = a.Firewall.Migrate(job.Context, c.DNS.Redirect); err != nil {
				return err
			}
		} else {
			pending, err = a.Firewall.Apply(job.Context, fmt.Sprintf("revision-%d", job.Revision), c.Firewall, c.DNS.Redirect)
			if err != nil {
				return err
			}
		}
	}
	if pending.Status == "pending" {
		a.Client.Send(protocol.New("firewall.pending", job.ID, job.Revision, pending), true)
	}
	a.firewallInitialized = true
	return nil
}
