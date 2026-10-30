package agent

import (
	"context"
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) handle(ctx context.Context, m protocol.Message) {
	fail := func(e error) {
		a.Client.Send(protocol.New("error", m.ID, m.Revision, map[string]string{"error": a.Logs.Redact(e.Error())}), true)
	}
	switch m.Type {
	case "compute.announce", "compute.grant", "compute.ack", "compute.cancel":
		a.receiveCompute(ctx, m)
		return
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
		changes := protocol.Classify(a.desired, c)
		a.desired = c
		a.hasDesired = true
		a.desiredCached = false
		if a.utilityContext == nil || changes.Utilities || changes.Assets || changes.Certificates {
			if a.utilityCancel != nil {
				a.utilityCancel()
			}
			a.utilityContext, a.utilityCancel = context.WithCancel(ctx)
			a.lastDDNS = map[string]time.Time{}
		}
		a.retryAt = time.Time{}
		a.retryDelay = 0
		if m.Type == "user.controls" && !a.materialPending && !a.applying.Load() && d.ConfigRevision == d.Revision && a.Runtime.Overlay(c) {
			if e = a.Store.Accept(c, m.Revision); e != nil {
				fail(e)
				return
			}
			a.desiredCached = true
			a.Client.Send(protocol.New("state.accepted", m.ID, m.Revision, map[string]uint64{"authorization_revision": m.Revision}), true)
			a.Client.Send(protocol.New("state.applied", m.ID, m.Revision, map[string]bool{"ready": true}), true)
			return
		}
		a.queue(ctx, applyJob{ID: m.ID, Revision: m.Revision, Config: c})
		a.Client.Send(protocol.New("state.accepted", m.ID, m.Revision, map[string]uint64{"authorization_revision": m.Revision}), true)
	case "ddns.changes.ack":
		var ack protocol.DDNSChangeAck
		if e := protocol.Decode(m.Data, &ack); e != nil || a.ddnsJournal == nil {
			fail(errors.New("invalid DDNS acknowledgment"))
		} else if e = a.ddnsJournal.Acknowledge(ack.IDs); e != nil {
			fail(e)
		}
	case "firewall.events.ack":
		var ack protocol.FirewallEventAck
		if e := protocol.Decode(m.Data, &ack); e != nil || len(ack.IDs) > protocol.MaxFirewallEventsPerFrame {
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
		} else if advanced, e := a.Store.Acknowledge(p.ID); e != nil {
			a.failStorage(e)
			fail(e)
		} else if advanced {
			a.requestReports(reportReplay)
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
