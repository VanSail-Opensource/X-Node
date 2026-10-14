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
	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/host"
	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/monitor"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	"github.com/VanSail-Opensource/X-Node/internal/speedtest"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	updatepkg "github.com/VanSail-Opensource/X-Node/internal/update"
	"github.com/VanSail-Opensource/X-Node/pkg/releases"
)

type applyJob struct {
	ID         string
	Revision   uint64
	Config     protocol.Config
	Cached     bool
	Context    context.Context
	Generation uint64
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
	notify             chan string
	generation         uint64
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
	a := &Agent{Dir: dir, Version: version, BootID: state.ID(), Store: store, Registry: registry, Runtime: xray.New(registry), Client: client, Logs: logs, Sampler: monitor.New(), Certificates: cert.NewPool(filepath.Join(dir, "certs")), Runner: runner, apply: make(chan applyJob, 1), applied: make(chan applied, 1), bans: make(chan banEvent, 128), previous: state.Traffic{}, lastDDNS: map[string]time.Time{}, notify: make(chan string, 1)}
	a.Firewall = &firewall.Manager{Dir: filepath.Join(dir, "firewall"), ConfigPath: "/etc/nftables.conf", Executable: "/usr/local/bin/xnodectl", Runner: runner}
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

var Capabilities = []string{"native_xray", "multi_inbound", "tcp_udp_limits", "session_revocation", "traffic_ack", "certificates", "ddns", "smartdns", "geodata", "nftables", "port_forward", "metrics", "logs", "peer_speedtest", "torrent_ban", "signed_updates", "traffic_periods_v1", "measured_user_rates", "authorization_expiry", "member_outbound_guards", "traffic_period_barriers_v1", "config_validation_v1", "volatile_connection_controls_v1"}

func (a *Agent) Run(ctx context.Context) error {
	d := a.Store.Snapshot()
	a.Registry.SetUsers(d.Users)
	a.Registry.RestoreBans(d.Bans)
	a.Registry.RestoreIPBlocks(d.IPBlocks)
	if d.Config != nil {
		a.desired = protocol.Clone(*d.Config)
		a.desired.Users = d.Users
		a.hasDesired = true
		a.registerSecrets(a.desired)
		a.Registry.SetPorts(a.desired.BlockedPorts)
		a.Registry.SetReportIPs(a.desired.Telemetry.IncludeActiveIPs)
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: true})
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
	go a.applyLoop(child)
	defer a.Certificates.Stop()
	defer a.Runtime.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			if a.cancelApply != nil {
				a.cancelApply()
			}
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
			if done.Job.Generation == a.generation {
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
				}
			}
			if done.Error != nil {
				a.Client.Send(protocol.New("state.failed", done.Job.ID, done.Job.Revision, map[string]string{"error": a.Logs.Redact(done.Error.Error())}), true)
			} else {
				a.Client.Send(protocol.New("state.applied", done.Job.ID, done.Job.Revision, map[string]any{"ready": a.Runtime.Ready()}), true)
			}
			a.sendStatus()
		case id := <-a.notify:
			if a.hasDesired {
				a.Runtime.Stop()
				d := a.Store.Snapshot()
				a.queue(child, applyJob{ID: id, Revision: d.Revision, Config: a.desired, Cached: true})
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
	if job.Context.Err() != nil {
		return job.Context.Err()
	}
	c := protocol.Clone(job.Config)
	p, e := geodata.FromNative(c.Xray)
	if e != nil {
		return e
	}
	if e = a.ensureAssets(job.Context, c, p, false); e != nil {
		return e
	}
	resolved, e := a.Certificates.Prepare(lifetime, c)
	if e != nil {
		return e
	}
	if job.Context.Err() != nil {
		return job.Context.Err()
	}
	if _, e = xray.Prepare(resolved); e != nil {
		return e
	}
	// Remove the previous redirect before changing resolver ownership.
	if e = a.Firewall.EnableConfirmedDNS(job.Context, false); e != nil {
		return e
	}
	if c.DNS.Mode != "smartdns" {
		marker := filepath.Join(a.Dir, "smartdns-managed")
		if _, e := os.Stat(marker); e == nil {
			if _, e = a.Runner.Run(job.Context, "systemctl", "disable", "--now", "smartdns.service"); e != nil {
				return e
			}
		}
	}
	if c.DNS.Mode == "smartdns" {
		a.Runtime.Stop()
		if e = dns.ConfigureSmartDNS(job.Context, c.DNS, a.Runner); e != nil {
			return e
		}
		if e = state.AtomicWrite(filepath.Join(a.Dir, "smartdns-managed"), []byte("managed\n"), 0600); e != nil {
			return e
		}
	}
	// Every native asset path resolves inside the managed directory.
	var native map[string]any
	_ = json.Unmarshal(resolved.Xray, &native)
	env, _ := native["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	env["XRAY_LOCATION_ASSET"] = geodata.Resolve(filepath.Join(a.Dir, "geodata"))
	native["env"] = env
	resolved.Xray, _ = json.Marshal(native)
	if a.Store.Snapshot().Revision != job.Revision {
		return errors.New("configuration superseded")
	}
	resolved.Users = a.Store.Snapshot().Users
	if e = a.Runtime.Apply(lifetime, resolved); e != nil {
		return e
	}
	if job.Context.Err() != nil {
		return job.Context.Err()
	}
	if c.DNS.Redirect {
		if e = dns.ResolverReady(job.Context); e != nil {
			return e
		}
	}
	if e = a.Store.Accept(c, job.Revision); e != nil {
		return e
	}
	a.Certificates.Commit(c)
	a.Sampler.Interval(c.SampleInterval())
	nextGeo := geodata.Next(p, time.Now())
	if nextGeo.IsZero() {
		a.geoNext.Store(0)
	} else {
		a.geoNext.Store(nextGeo.UnixNano())
	}
	if c.Firewall.Enabled && !job.Cached {
		pending, e := a.Firewall.Apply(job.Context, fmt.Sprintf("revision-%d", job.Revision), c.Firewall, c.DNS.Redirect)
		if e != nil {
			return e
		}
		a.Client.Send(protocol.New("firewall.pending", job.ID, job.Revision, pending), true)
	}
	if job.Cached {
		_ = a.Firewall.EnableConfirmedDNS(job.Context, c.DNS.Redirect)
	}
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
		if a.Updater != nil && a.Updater.Pending() && managedExtensions(c) && !managedExtensions(a.desired) {
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
		if a.utilityCancel != nil {
			a.utilityCancel()
		}
		a.utilityContext, a.utilityCancel = context.WithCancel(ctx)
		a.lastDDNS = map[string]time.Time{}
		a.retryAt = time.Time{}
		a.retryDelay = 0
		a.queue(ctx, applyJob{ID: m.ID, Revision: m.Revision, Config: c})
		a.Client.Send(protocol.New("state.accepted", m.ID, m.Revision, map[string]uint64{"authorization_revision": m.Revision}), true)
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
	if !a.Runtime.Ready() && !a.applying.Load() && !now.Before(a.retryAt) {
		d := a.Store.Snapshot()
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: true})
	}
	if !a.applying.Load() && a.Certificates.Renewed() {
		d := a.Store.Snapshot()
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: true})
	}
	a.scheduleUtilities(ctx, now)
}
func (a *Agent) command(ctx context.Context, m protocol.Message) error {
	var request struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	}
	if e := protocol.Decode(m.Data, &request); e != nil {
		return e
	}
	args := request.Args
	if len(args) == 0 {
		args = []byte("{}")
	}
	snapshot := a.Store.Snapshot()
	var configuration protocol.Config
	if snapshot.Config != nil {
		configuration = protocol.Clone(*snapshot.Config)
	}
	return a.Jobs.Start(ctx, m.ID, request.Name, func(ctx context.Context, progress func(any)) (any, error) {
		switch request.Name {
		case "traffic.flush":
			return a.flushTraffic(ctx, args)
		case "config.validate":
			config, err := protocol.ParseConfig(args)
			if err != nil {
				return nil, err
			}
			if _, err = xray.Prepare(config); err != nil {
				return nil, errors.New("native configuration validation failed")
			}
			return map[string]bool{"valid": true}, nil
		case "connections.list":
			var p struct {
				After string `json:"after,omitempty"`
				Limit int    `json:"limit,omitempty"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			return a.Registry.List(p.After, p.Limit), nil
		case "users.active_ips":
			var p struct {
				UserID int `json:"user_id,omitempty"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			if p.UserID < 0 {
				return nil, errors.New("invalid user ID")
			}
			return a.Registry.ActiveIPs(p.UserID), nil
		case "ips.control":
			var p protocol.IPControl
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			ip, e := sessions.CanonicalIP(p.SourceIP)
			if e != nil {
				return nil, e
			}
			if p.UserID < 0 || p.BlockSeconds < 0 || p.BlockSeconds > 604800 || p.Unblock && p.BlockSeconds > 0 || !p.Drop && !p.Unblock && p.BlockSeconds == 0 {
				return nil, errors.New("invalid IP control")
			}
			key := sessions.IPBlockKey(p.UserID, ip)
			block := protocol.IPBlock{SourceIP: ip, UserID: p.UserID}
			if p.BlockSeconds > 0 {
				block.Until = time.Now().Add(time.Duration(p.BlockSeconds) * time.Second)
			}
			if p.BlockSeconds > 0 || p.Unblock {
				if e = a.Store.BlockIP(key, block); e != nil {
					return nil, e
				}
				a.Registry.SetIPBlock(key, block)
			}
			dropped := 0
			if p.Drop {
				dropped = a.Registry.DropIP(ip, p.UserID)
			}
			return map[string]any{"source_ip": ip, "user_id": p.UserID, "dropped": dropped, "blocked_until": block.Until}, nil
		case "connections.close":
			var p struct {
				ID         string `json:"id"`
				UserID     int    `json:"user_id,omitempty"`
				InboundTag string `json:"inbound_tag,omitempty"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			if p.UserID > 0 {
				a.Registry.CloseUser(p.UserID, p.InboundTag)
				return map[string]bool{"closed": true}, nil
			}
			return map[string]bool{"closed": a.Registry.CloseConnection(p.ID)}, nil
		case "metrics.get":
			return a.Sampler.Snapshot(), nil
		case "certificates.get":
			return a.Certificates.Status(), nil
		case "runtime.reload":
			select {
			case a.notify <- m.ID:
				return map[string]bool{"queued": true}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "geodata.refresh":
			p, e := geodata.FromNative(configuration.Xray)
			if e != nil {
				return nil, e
			}
			if e = a.ensureAssets(ctx, configuration, p, true); e != nil {
				return nil, e
			}
			select {
			case a.notify <- m.ID:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return map[string]bool{"refreshed": true}, nil
		case "ddns.run":
			var p struct {
				ID string `json:"job_id"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			for _, job := range configuration.DDNS {
				if job.ID == p.ID {
					a.dnsMu.Lock()
					defer a.dnsMu.Unlock()
					provider, e := dns.Provider(configuration.Providers[job.Provider])
					if e != nil {
						return nil, e
					}
					return dns.DDNS(ctx, job, provider, nil)
				}
			}
			return nil, errors.New("unknown DDNS job")
		case "jobs.list":
			return a.Jobs.Snapshot(), nil
		case "firewall.status":
			return a.Firewall.Status(), nil
		case "firewall.confirm":
			var p struct {
				ID string `json:"transaction_id"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			return map[string]bool{"confirmed": true}, a.Firewall.Confirm(ctx, p.ID)
		case "firewall.apply":
			var p struct {
				Policy      protocol.FirewallPolicy `json:"policy"`
				DNSRedirect bool                    `json:"dns_redirect,omitempty"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			if p.DNSRedirect {
				if e := dns.ResolverReady(ctx); e != nil {
					return nil, e
				}
			}
			return a.Firewall.Apply(ctx, m.ID, p.Policy, p.DNSRedirect)
		case "speedtest":
			var p speedtest.Request
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			return speedtest.Run(ctx, p, func(stage string) { progress(map[string]string{"stage": stage}) })
		case "update.check":
			return a.Updater.Check(ctx, "")
		case "update.install":
			var p struct {
				Version string `json:"version,omitempty"`
			}
			if e := protocol.Decode(args, &p); e != nil {
				return nil, e
			}
			return a.Updater.Install(ctx, m.ID, p.Version, progress)
		case "update.rollback":
			return map[string]bool{"rolled_back": true}, a.Updater.Rollback(ctx)
		default:
			return nil, errors.New("unsupported utility command")
		}
	})
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
