package agent

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/dns"
	"github.com/VanSail-Opensource/X-Node/internal/geodata"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/speedtest"
)

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
	// Recovery reads must remain available while both utility jobs are busy.
	if request.Name == "update.status" || request.Name == "jobs.list" {
		var data any
		if request.Name == "update.status" {
			data = a.Updater.Status()
		} else {
			data = a.Jobs.Snapshot()
		}
		a.Client.Send(protocol.New("command.result", m.ID, 0, JobResult{ID: m.ID, Command: request.Name, Status: "completed", Data: data, Finished: time.Now().UTC()}), true)
		return nil
	}
	var configuration protocol.Config
	switch request.Name {
	case "ddns.run", "firewall.apply":
		configuration, _ = a.Store.Configuration()
	}
	start := a.Jobs.Start
	switch request.Name {
	case "traffic.flush", "firewall.confirm", "firewall.bans.update":
		start = a.Jobs.StartControl
	case "firewall.bans.sync":
		var chunk struct {
			SourcesOnly bool `json:"sources_only"`
		}
		if json.Unmarshal(args, &chunk) == nil && !chunk.SourcesOnly {
			start = a.Jobs.StartControl
		}
	}
	return start(ctx, m.ID, request.Name, func(ctx context.Context, progress func(any)) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, protocol.CommandTimeout(request.Name))
		defer cancel()
		switch request.Name {
		case "traffic.flush":
			return a.flushTraffic(ctx, args)
		case "config.validate":
			config, err := protocol.ParseConfig(args)
			if err != nil {
				return nil, err
			}
			a.nativeMu.Lock()
			defer a.nativeMu.Unlock()
			policy, err := geodata.FromNative(config.Xray)
			if err != nil {
				return nil, err
			}
			if err = a.validateNative(ctx, config, policy); err != nil {
				return nil, err
			}
			return map[string]bool{"valid": true}, nil
		case "connections.list", "users.active_ips", "ips.control", "connections.close":
			return a.connectionCommand(request.Name, args)
		case "metrics.get":
			return a.Sampler.Snapshot(), nil
		case "certificates.get":
			return a.Certificates.Status(), nil
		case "runtime.reload":
			return a.reloadRuntime(ctx, m.ID)
		case "geodata.refresh":
			return a.reloadRuntime(ctx, m.ID, true)
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
		case "firewall.bans.sync", "firewall.bans.update":
			var update protocol.FirewallUpdate
			if e := protocol.Decode(args, &update); e != nil {
				return nil, e
			}
			if request.Name == "firewall.bans.sync" {
				if e := a.Guard.Sync(ctx, update); e != nil {
					return nil, e
				}
			} else {
				if e := a.Guard.Update(ctx, update); e != nil {
					return nil, e
				}
			}
			return map[string]bool{"applied": true}, nil
		case "firewall.geoip.sync":
			var chunk protocol.GeoIPChunk
			if err := protocol.Decode(args, &chunk); err != nil {
				return nil, err
			}
			ready, err := a.Guard.SyncGeoIP(ctx, chunk)
			return map[string]bool{"ready": ready}, err
		case "firewall.bans.get":
			return a.Guard.Status(), nil
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
			candidate := protocol.Clone(configuration)
			candidate.Firewall = p.Policy
			if err := protocol.ValidateNativePolicies(candidate); err != nil {
				return nil, err
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
