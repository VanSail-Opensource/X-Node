// Package agent serializes authoritative state while utility work runs independently.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/monitor"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	updatepkg "github.com/VanSail-Opensource/X-Node/internal/update"
	"github.com/VanSail-Opensource/X-Node/pkg/releases"
)

type applyJob struct {
	Done          chan error
	Reload        bool
	RefreshAssets bool
	ID            string
	Revision      uint64
	Config        protocol.Config
	Cached        bool
	Context       context.Context
	Generation    uint64
}
type applied struct {
	Job   applyJob
	Error error
}
type banEvent struct {
	ID    int
	Until time.Time
}
type Agent struct {
	Guard              *firewall.Guard
	Dir                string
	Version            string
	BootID             string
	Store              *state.Store
	Registry           *sessions.Registry
	Runtime            *xray.Runtime
	Client             *transport.Client
	Logs               *nlog.Stream
	Sampler            *monitor.Sampler
	Certificates       *cert.Pool
	Firewall           *firewall.Manager
	Updater            *updatepkg.Manager
	Runner             host.Runner
	Jobs               *Jobs
	desired            protocol.Config
	desiredCached      bool
	hasDesired         bool
	apply              chan applyJob
	applied            chan applied
	cancelApply        context.CancelFunc
	applying           atomic.Bool
	bans               chan banEvent
	previous           state.Traffic
	previousAccounting map[string][2]uint64
	lastCapture        time.Time
	accountingRequests chan accountingRequest
	lastReport         time.Time
	lastDDNS           map[string]time.Time
	lastUpdate         time.Time
	geoNext            atomic.Int64
	geoFailures        int
	geoPolicy          string
	geoRunning         atomic.Bool
	notify             chan reloadRequest
	reloadDone         chan error
	generation         uint64
	nativeMu           sync.Mutex
	geoCandidate       string
	geoCandidateKey    string
	geoMu              sync.Mutex
	dnsMu              sync.Mutex
	utilityCancel      context.CancelFunc
	utilityContext     context.Context
	retryAt            time.Time
	retryDelay         time.Duration
}

func New(dir, version string, client *transport.Client, logs *nlog.Stream) (*Agent, error) {
	metadata, err := releases.ExecutableMetadata()
	if err != nil {
		return nil, err
	}
	store, e := state.Open(dir)
	if e != nil {
		return nil, e
	}
	runner := host.Commands{}
	registry := sessions.New()
	a := &Agent{Dir: dir, Version: version, BootID: state.ID(), Store: store, Registry: registry, Runtime: xray.New(registry), Client: client, Logs: logs, Sampler: monitor.New(), Certificates: cert.NewPool(filepath.Join(dir, "certs")), Runner: runner, apply: make(chan applyJob, 1), applied: make(chan applied, 1), bans: make(chan banEvent, 128), previous: state.Traffic{}, lastDDNS: map[string]time.Time{}, notify: make(chan reloadRequest, 1)}
	if cached := store.Snapshot(); cached.Config != nil {
		a.Certificates.RetainStored(*cached.Config)
	}
	a.Firewall = &firewall.Manager{Dir: filepath.Join(dir, "firewall"), ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner}
	a.Guard, e = firewall.OpenGuard(filepath.Join(dir, "firewall"), a.Firewall)
	if e != nil {
		return nil, e
	}
	a.Runtime.SetInboundObserver(func(event xray.InboundObservation) { a.Guard.Observe(event.IP, event.Rule) })
	a.previousAccounting = map[string][2]uint64{}
	a.accountingRequests = make(chan accountingRequest, 16)
	a.Updater = updatepkg.New(filepath.Join(dir, "updates"), version, runner)
	a.Jobs, e = NewJobs(dir, client.Send)
	if e != nil {
		return nil, e
	}
	a.Jobs.redact = logs.Redact
	registry.OnBan = func(id int, until time.Time) {
		if e := store.Ban(id, until); e != nil {
			registry.Pause(true)
			client.Send(protocol.New("agent.error", "", 0, map[string]string{"error": "durable ban persistence failed"}), true)
		}
		select {
		case a.bans <- banEvent{ID: id, Until: until}:
		default:
			client.Send(protocol.New("torrent.detected", "", 0, map[string]any{"user_id": id, "until": until}), false)
		}
	}
	registry.OnReject = func(event sessions.AdmissionEvent) {
		client.Send(protocol.New("admission.rejected", "", 0, event), false)
	}
	client.Hello = func() protocol.Message {
		d := store.Snapshot()
		return protocol.New("agent.hello", "", d.Revision, map[string]any{"agent_id": d.AgentID, "boot_id": a.BootID, "version": version, "xray_version": "v26.10.10", "config_revision": d.ConfigRevision, "ready": a.Runtime.Ready(), "capabilities": Capabilities, "upgrade_pending": a.Updater.Pending(), "binary_sha256": metadata.SHA256, "platform": metadata.Platform})
	}
	return a, nil
}

var Capabilities = []string{"activation_commands_v1", "update_transaction_v1", "firewall_cidr_exemptions_v1", "source_geoip_stream_v1", "disk_firewall_sources_v1", "node_file_certificates_v1", "xtables_compat_snapshot_v1", "host_firewall_ownership_v1", "sampled_activity_v1", "transit_credentials_v1", "source_geoip_firewall_v1", "shared_domain_blocks_v1", "geodata_interval_v1", "native_firewall_v1", "firewall_control_v1", "native_xray", "multi_inbound", "tcp_udp_limits", "session_revocation", "traffic_ack", "certificates", "ddns", "xray_scoped_dns_v1", "geodata", "nftables", "port_forward", "metrics", "logs", "peer_speedtest", "torrent_ban", "signed_updates", "traffic_periods_v1", "measured_user_rates", "authorization_expiry", "member_outbound_guards", "traffic_period_barriers_v1", "config_validation_v1", "volatile_connection_controls_v1", "native_auxiliary_inbounds_v1"}

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
	defer func() {
		if a.utilityCancel != nil {
			a.utilityCancel()
		}
	}()
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
				a.queue(request.Context, applyJob{ID: request.ID, Revision: a.Store.Revision(), Config: a.desired, Cached: a.desiredCached, Reload: true, RefreshAssets: request.RefreshAssets, Done: request.Done})
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
func (a *Agent) failStorage(err error) {
	a.Registry.Pause(true)
	a.Runtime.Stop()
	nlog.Core().Error("durable state unavailable; proxy admission stopped")
	a.Client.Send(protocol.New("agent.error", "", 0, map[string]string{"error": "durable state unavailable"}), true)
}
func (a *Agent) registerSecrets(c protocol.Config) {
	values := []string{a.Client.Token}
	for _, u := range c.Users {
		values = append(values, u.UUID)
		for _, raw := range u.Credentials {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			for _, v := range m {
				if secret, ok := v.(string); ok {
					values = append(values, secret)
				}
			}
		}
	}
	for _, p := range c.Providers {
		for _, secret := range p.Credentials {
			values = append(values, secret)
		}
	}
	for _, p := range c.Certificates {
		values = append(values, p.Config.KeyContent)
		for _, secret := range p.Config.DNSEnv {
			values = append(values, secret)
		}
	}
	var native any
	_ = json.Unmarshal(c.Xray, &native)
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			for key, value := range node {
				switch strings.ToLower(key) {
				case "id", "password", "auth", "token", "privatekey", "key", "pass":
					if secret, ok := value.(string); ok {
						values = append(values, secret)
					}
				}
				walk(value)
			}
		case []any:
			for _, item := range node {
				walk(item)
			}
		}
	}
	walk(native)
	a.Logs.SetSecrets(values...)
}
func (a *Agent) queue(ctx context.Context, job applyJob) {
	finishReload(a.reloadDone, errors.New("configuration superseded"))
	a.reloadDone = job.Done
	if a.cancelApply != nil {
		a.cancelApply()
	}
	a.generation++
	job.Generation = a.generation
	child, cancel := context.WithCancel(ctx)
	a.cancelApply = cancel
	job.Context = child
	select {
	case a.apply <- job:
	default:
		select {
		case <-a.apply:
		default:
		}
		a.apply <- job
	}
	a.applying.Store(true)
}
func (a *Agent) applyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.apply:
			err := a.activate(ctx, job)
			select {
			case a.applied <- applied{Job: job, Error: err}:
			case <-ctx.Done():
				return
			}
		}
	}
}
func (a *Agent) activate(lifetime context.Context, job applyJob) error {
	a.nativeMu.Lock()
	defer a.nativeMu.Unlock()
	if job.Context.Err() != nil {
		return job.Context.Err()
	}
	c := protocol.Clone(job.Config)
	p, e := geodata.FromNative(c.Xray)
	if e != nil {
		return e
	}
	if job.RefreshAssets {
		target, err := a.ensureAssets(job.Context, c, p, true)
		if err != nil {
			return err
		}
		a.geoCandidate, a.geoCandidateKey = target, assetKey(c, p)
	}
	resolved, assetDir, e := a.prepareNative(job.Context, lifetime, c, p)
	if e != nil {
		return e
	}
	if !job.Cached {
		if e = a.Store.Stage(c, job.Revision); e != nil {
			return e
		}
	}
	// Remove the previous redirect before changing resolver ownership.
	if e = a.Firewall.EnableConfirmedDNS(job.Context, false); e != nil {
		return e
	}
	if a.Store.Snapshot().Revision != job.Revision {
		return errors.New("configuration superseded")
	}
	resolved.Users = a.Store.Snapshot().Users
	if e = a.Runtime.Apply(lifetime, resolved, job.Reload); e != nil {
		return e
	}
	if job.Context.Err() != nil {
		return job.Context.Err()
	}
	a.Sampler.Interval(c.SampleInterval())
	a.scheduleGeodata(p)
	if !c.Firewall.Enabled {
		if e = a.Firewall.RestoreOriginal(job.Context); e != nil {
			return e
		}
	}
	if c.Firewall.Enabled && !job.Cached {
		pending, e := a.Firewall.Apply(job.Context, fmt.Sprintf("revision-%d", job.Revision), c.Firewall, c.DNS.Redirect)
		if e != nil {
			return e
		}
		a.Client.Send(protocol.New("firewall.pending", job.ID, job.Revision, pending), true)
	}
	if job.Cached && c.Firewall.Enabled {
		if e = a.Firewall.Migrate(job.Context, c.DNS.Redirect); e != nil {
			return e
		}
		if e = a.Firewall.EnableConfirmedDNS(job.Context, c.DNS.Redirect); e != nil {
			return e
		}
	}
	a.Guard.Configure(c.Firewall)
	if e = a.Store.Accept(c, job.Revision); e != nil {
		return e
	}
	if len(p.Assets) > 0 {
		if e = geodata.Activate(filepath.Join(a.Dir, "geodata"), assetDir); e != nil {
			return e
		}
	}
	a.geoCandidate, a.geoCandidateKey = "", ""
	a.Certificates.Commit(c)
	if e = a.Updater.Confirm(job.Context); e != nil {
		return e
	}
	a.Registry.Pause(false)
	a.systemdReady()
	return nil
}
func (a *Agent) handle(ctx context.Context, m protocol.Message) {
	fail := func(e error) {
		a.Client.Send(protocol.New("error", m.ID, m.Revision, map[string]string{"error": a.Logs.Redact(e.Error())}), true)
	}
	switch m.Type {
	case "state.sync", "config.apply", "users.sync", "users.delta", "user.controls":
		d := a.Store.Snapshot()
		if m.Revision == 0 || m.Revision <= d.Revision {
			if m.Type == "state.sync" && m.Revision == d.ConfigRevision && a.Runtime.Ready() {
				a.Client.Send(protocol.New("state.applied", m.ID, m.Revision, map[string]bool{"ready": true}), true)
				return
			}
			fail(errors.New("stale revision"))
			return
		}
		if m.Type != "state.sync" && m.BaseRevision != d.Revision {
			a.Client.Send(protocol.New("state.request", m.ID, d.Revision, map[string]string{"reason": "revision_gap"}), true)
			return
		}
		var c protocol.Config
		var e error
		if m.Type == "state.sync" || m.Type == "config.apply" {
			c, e = protocol.ParseConfig(m.Data)
		} else {
			if !a.hasDesired {
				fail(errors.New("full baseline required"))
				return
			}
			c = protocol.Clone(a.desired)
			switch m.Type {
			case "users.sync":
				var p protocol.UsersSync
				e = protocol.Decode(m.Data, &p)
				if e == nil {
					if p.Users == nil {
						e = errors.New("users must be an explicit array")
					} else {
						c.Users = *p.Users
					}
				}
			case "users.delta":
				var p protocol.UsersDelta
				e = protocol.Decode(m.Data, &p)
				if e == nil {
					users := map[int]protocol.User{}
					for _, u := range d.Users {
						users[u.ID] = u
					}
					for _, id := range p.Remove {
						delete(users, id)
					}
					for _, u := range p.Upsert {
						users[u.ID] = u
					}
					c.Users = []protocol.User{}
					for _, u := range users {
						c.Users = append(c.Users, u)
					}
				}
			case "user.controls":
				var p protocol.UserControls
				e = protocol.Decode(m.Data, &p)
				if e == nil {
					if p.Users == nil {
						e = errors.New("users must be an explicit array")
						break
					}
					controls := map[int]bool{}
					for _, u := range p.Users {
						if _, ok := controls[u.ID]; ok {
							e = errors.New("duplicate user control")
							break
						}
						controls[u.ID] = u.BlockNew
					}
					if e != nil {
						break
					}
					for i := range c.Users {
						if v, ok := controls[c.Users[i].ID]; ok {
							c.Users[i].BlockNew = v
							delete(controls, c.Users[i].ID)
						}
					}
					if len(controls) > 0 {
						e = errors.New("control references unknown user")
					}
				}
			}
			if e == nil {
				e = c.Validate()
			}
		}
		if e != nil {
			fail(e)
			return
		}
		if a.Updater != nil && a.Updater.Pending() && adoptsManagedExtensions(c, a.desired) {
			fail(errors.New("upgrade confirmation is required before adopting managed extensions"))
			return
		}
		if e = a.Store.Authorize(c.Users, m.Revision); e != nil {
			fail(e)
			return
		}
		a.registerSecrets(c)
		a.Registry.SetUsers(c.Users)
		a.Registry.SetPorts(c.BlockedPorts)
		a.Registry.SetReportIPs(c.Telemetry.IncludeActiveIPs)
		a.desired = c
		a.hasDesired = true
		a.desiredCached = false
		if a.utilityCancel != nil {
			a.utilityCancel()
		}
		a.utilityContext, a.utilityCancel = context.WithCancel(ctx)
		a.lastDDNS = map[string]time.Time{}
		a.retryAt = time.Time{}
		a.retryDelay = 0
		a.queue(ctx, applyJob{ID: m.ID, Revision: m.Revision, Config: c})
		a.Client.Send(protocol.New("state.accepted", m.ID, m.Revision, map[string]uint64{"authorization_revision": m.Revision}), true)
	case "firewall.events.ack":
		var ack protocol.FirewallEventAck
		if e := protocol.Decode(m.Data, &ack); e != nil || len(ack.IDs) > 512 {
			fail(errors.New("invalid firewall event acknowledgment"))
		} else {
			a.Guard.Acknowledge(ack.IDs)
		}
	case "traffic.ack":
		var p struct {
			ID string `json:"id"`
		}
		if e := protocol.Decode(m.Data, &p); e != nil {
			fail(e)
		} else if e = a.Store.Ack(p.ID); e != nil {
			fail(e)
		}
	case "command":
		if e := a.command(ctx, m); e != nil {
			fail(e)
		}
	case "command.cancel":
		var p struct {
			ID string `json:"id"`
		}
		if e := protocol.Decode(m.Data, &p); e != nil {
			fail(e)
		} else {
			a.Client.Send(protocol.New("command.cancelled", m.ID, 0, map[string]bool{"cancelled": a.Jobs.Cancel(p.ID)}), true)
		}
	default:
		fail(errors.New("unsupported message type"))
	}
}
func (a *Agent) sendStatus() {
	d := a.Store.Snapshot()
	summary := a.Registry.Summary()
	synchronized := d.Config != nil && d.ConfigRevision == d.Revision && !a.applying.Load()
	a.Client.Send(protocol.New("telemetry.report", "", d.Revision, map[string]any{"agent_id": d.AgentID, "boot_id": a.BootID, "time": time.Now().UTC(), "connected": a.Client.Connected(), "liveness": true, "ready": a.Runtime.Ready(), "synchronized": synchronized, "config_revision": d.ConfigRevision, "users": summary, "machine": a.Sampler.Snapshot(), "certificates": a.Certificates.Status(), "transport_dropped": a.Client.Dropped()}), false)
	notifySystemd(fmt.Sprintf("STATUS=Runtime ready=%t synchronized=%t connected=%t authorization=%d configuration=%d", a.Runtime.Ready(), synchronized, a.Client.Connected(), d.Revision, d.ConfigRevision))
	status, _ := json.Marshal(map[string]any{"liveness": true, "ready": a.Runtime.Ready(), "connected": a.Client.Connected(), "revision": d.Revision, "config_revision": d.ConfigRevision, "updated": time.Now().UTC()})
	_ = state.AtomicWrite(filepath.Join(a.Dir, "status.json"), status, 0600)
}
func (a *Agent) periodic(ctx context.Context) {
	if !a.hasDesired {
		return
	}
	now := time.Now()
	if now.Sub(a.lastReport) >= a.desired.ReportInterval() {
		a.lastReport = now
		a.sendStatus()
		if batch, e := a.Store.Batch(); e != nil {
			a.failStorage(e)
		} else if batch != nil {
			a.Client.Send(protocol.New("traffic.report", batch.ID, 0, batch), true)
		}
		entries, dropped := a.Logs.Drain()
		if len(entries) > 0 || dropped > 0 {
			a.Client.Send(protocol.New("logs.report", "", 0, map[string]any{"entries": entries, "dropped": dropped}), false)
		}
	}
	if (!a.Runtime.Ready() || !a.retryAt.IsZero()) && !a.applying.Load() && !now.Before(a.retryAt) {
		d := a.Store.Snapshot()
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached})
	}
	if !a.applying.Load() && a.Certificates.Renewed() {
		d := a.Store.Snapshot()
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached})
	}
	a.scheduleUtilities(ctx, now)
}
func (a *Agent) systemdReady() { notifySystemd("READY=1\nSTATUS=Proxy runtime ready\nWATCHDOG=1") }
func notifySystemd(message string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	connection, e := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if e != nil {
		return
	}
	_, _ = connection.Write([]byte(message))
	_ = connection.Close()
}
