package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) Run(ctx context.Context) error {
	if err := a.Firewall.RestoreFile(ctx); err != nil {
		return fmt.Errorf("restore confirmed firewall: %w", err)
	}
	d := a.Store.Snapshot()
	a.Registry.SetUsers(d.Users)
	a.Registry.RestoreBans(d.Bans)
	a.Registry.RestoreIPBlocks(d.IPBlocks)
	startup := d.Config
	if d.DesiredConfig != nil {
		startup = d.DesiredConfig
	}
	if startup != nil {
		a.desired = protocol.Clone(*startup)
		a.desired.Users = d.Users
		a.hasDesired = true
		a.Guard.Configure(a.desired.Firewall)
		a.registerSecrets(a.desired)
		a.Registry.SetPorts(a.desired.BlockedPorts)
		a.Registry.SetReportIPs(a.desired.Telemetry.IncludeActiveIPs)
		a.desiredCached = d.DesiredConfig == nil
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached})
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	reportsDone := make(chan struct{})
	go func() { defer close(reportsDone); a.runReports(child) }()
	defer func() { cancel(); <-reportsDone }()
	defer func() {
		if a.utilityCancel != nil {
			a.utilityCancel()
		}
	}()
	a.compute = newComputeWorker(a.Client.Send)
	a.compute.eligible = a.computeEligible
	computeDone := make(chan struct{})
	go func() { defer close(computeDone); a.compute.run(child) }()
	defer func() { cancel(); <-computeDone }()
	go a.Client.Run(child)
	go a.Sampler.Run(child)
	applyDone := make(chan struct{})
	go func() { defer close(applyDone); a.applyLoop(child) }()
	guardDone, kernelDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(guardDone); a.Guard.Run(child, a.Client.Send) }()
	go func() { defer close(kernelDone); a.Guard.RunKernel(child) }()
	defer func() { cancel(); <-guardDone; <-kernelDone }()
	defer a.Certificates.Stop()
	defer a.Runtime.Stop()
	stopApply := func() {
		cancel()
		if a.cancelApply != nil {
			a.cancelApply()
		}
		<-applyDone
	}
	defer stopApply()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stopApply()
			a.Runtime.Stop()
			if e := a.captureTraffic(); e != nil {
				return e
			}
			return nil
		case m := <-a.Client.Incoming:
			a.handle(child, m)
		case request := <-a.accountingRequests:
			a.handleAccounting(request)
		case connected := <-a.Client.Status:
			if !connected {
				a.compute.reset()
			}
			if connected {
				a.lastReport = time.Time{}
				a.sendStatus()
			}
		case event := <-a.bans:
			a.Client.Send(protocol.New("torrent.detected", "", 0, map[string]any{"user_id": event.ID, "until": event.Until}), true)
		case done := <-a.applied:
			finishReload(done.Job.Done, done.Error)
			if done.Job.Generation == a.generation {
				a.reloadDone = nil
				a.applying.Store(false)
				if done.Error != nil {
					if a.retryDelay == 0 {
						a.retryDelay = time.Second
					} else {
						a.retryDelay = min(60*time.Second, a.retryDelay*2)
					}
					a.retryAt = time.Now().Add(a.retryDelay)
				} else {
					a.retryDelay = 0
					a.retryAt = time.Time{}
					a.desiredCached = true
					a.materialPending = false
				}
			}
			if done.Error != nil {
				a.Client.Send(protocol.New("state.failed", done.Job.ID, done.Job.Revision, map[string]string{"error": a.Logs.Redact(done.Error.Error())}), true)
			} else {
				a.Client.Send(protocol.New("state.applied", done.Job.ID, done.Job.Revision, map[string]any{"ready": a.Runtime.Ready()}), true)
			}
			a.sendStatus()
		case request := <-a.notify:
			if request.Context.Err() != nil {
				finishReload(request.Done, request.Context.Err())
			} else if a.hasDesired {
				a.queue(request.Context, applyJob{ID: request.ID, Revision: a.Store.Revision(), Config: a.desired, Cached: a.desiredCached, ForceRebuild: request.Force, RefreshAssets: request.RefreshAssets, RecheckMaterial: true, Done: request.Done})
			} else {
				finishReload(request.Done, errors.New("full baseline required before reload"))
			}
		case <-tick.C:
			a.Registry.ExpireUsers(time.Now())
			if e := a.captureTraffic(); e != nil {
				a.failStorage(e)
			}
			for _, id := range a.Registry.ExpireBans(time.Now()) {
				if e := a.Store.Ban(id, time.Time{}); e != nil {
					a.failStorage(e)
				}
				a.Client.Send(protocol.New("torrent.expired", "", 0, map[string]int{"user_id": id}), true)
			}
			for _, key := range a.Registry.ExpireIPBlocks(time.Now()) {
				if e := a.Store.BlockIP(key, protocol.IPBlock{}); e != nil {
					a.failStorage(e)
				}
			}
			a.periodic(child)
		}
	}
}
