package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) Run(ctx context.Context) error {
	if err := a.Firewall.RestoreFile(ctx); err != nil {
		return fmt.Errorf("restore confirmed firewall: %w", err)
	}
	d := a.Store.Snapshot()
	a.Registry.ApplyAuthorization(a.Store.CurrentAuthorization())
	a.Registry.RestoreBans(d.Bans)
	startup := d.Config
	if d.DesiredConfig != nil {
		startup = d.DesiredConfig
	}
	if startup != nil {
		a.desired = protocol.Clone(*startup)
		a.Certificates.Declare(a.desired, d.Revision)
		a.desired.Users = d.Users
		a.hasDesired = true
		a.Guard.Configure(a.desired.Firewall)
		a.registerSecrets(a.desired)
		a.Registry.SetPorts(a.desired.BlockedPorts)
		a.desiredCached = d.DesiredConfig == nil
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached})
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stopHourly := a.runHourly(child)
	defer stopHourly()
	status, err := a.listenStatus(child)
	if err != nil {
		return err
	}
	defer status.Close()
	cadence := newCadence(a.desired)
	defer cadence.stop()
	a.lastCapture = time.Now()
	a.lastSample = a.lastCapture
	a.Sampler.Interval(a.desired.SampleInterval())
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
			stopHourly()
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
				a.requestReports(reportStatus | reportPeriodic)
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
			a.handleReloadRequest(request)
		case <-cadence.sample.C:
			if e := a.sampleTraffic(); e != nil {
				a.failStorage(e)
			}
		case <-cadence.report.C:
			if a.hasDesired {
				a.requestReports(reportStatus | reportPeriodic)
			}
		case <-tick.C:
			a.Registry.ExpireUsers(time.Now())
			for _, id := range a.Registry.ExpireBans(time.Now()) {
				if e := a.Store.Ban(id, time.Time{}); e != nil {
					a.failStorage(e)
				}
				a.Client.Send(protocol.New("torrent.expired", "", 0, map[string]int{"user_id": id}), true)
			}
			if authorization, e := a.Store.ExpireIPBlocks(time.Now()); e != nil {
				a.failStorage(e)
			} else if authorization.Sequence > 0 {
				a.Registry.ApplyAuthorization(authorization)
			}
			a.periodic(child)
		}
		cadence.update(a.desired)
	}
}
