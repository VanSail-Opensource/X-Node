package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
	"net"
	"os"
	"path/filepath"
	"time"
)

func (a *Agent) sendStatus() {
	d := a.Store.Snapshot()
	summary := a.Registry.Summary()
	synchronized := d.Config != nil && d.ConfigRevision == d.Revision && !a.applying.Load()
	report := protocol.TelemetryReport{AgentID: d.AgentID, BootID: a.BootID, Time: time.Now().UTC(), Connected: a.Client.Connected(), Liveness: true, Ready: a.Runtime.Ready(), Synchronized: synchronized, ConfigRevision: d.ConfigRevision, Users: summary, Machine: telemetryJSON(a.Sampler.Snapshot()), Certificates: telemetryJSON(a.Certificates.Status()), TransportDropped: a.Client.Dropped()}
	var message protocol.Message
	if a.Client.CompactTelemetry() {
		message = protocol.New("telemetry.compact", "", d.Revision, protocol.CompactTelemetry(report))
	} else {
		message = protocol.New("telemetry.report", "", d.Revision, report)
	}
	a.Client.Send(message, false)
	notifySystemd(fmt.Sprintf("STATUS=Runtime ready=%t synchronized=%t connected=%t authorization=%d configuration=%d", a.Runtime.Ready(), synchronized, a.Client.Connected(), d.Revision, d.ConfigRevision))
	status, _ := json.Marshal(map[string]any{"liveness": true, "ready": a.Runtime.Ready(), "connected": a.Client.Connected(), "revision": d.Revision, "config_revision": d.ConfigRevision, "updated": time.Now().UTC()})
	_ = state.AtomicWrite(filepath.Join(a.Dir, "status.json"), status, 0600)
}

func telemetryJSON(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		nlog.Core().Warn("telemetry field could not be encoded")
		return nil
	}
	return raw
}
func (a *Agent) periodic(ctx context.Context) {
	if !a.hasDesired {
		return
	}
	now := time.Now()
	if now.Sub(a.lastReport) >= a.desired.ReportInterval() {
		a.lastReport = now
		a.sendStatus()
		if a.ddnsJournal != nil && a.Client.DDNSChanges() {
			if changes := a.ddnsJournal.Pending(); len(changes) > 0 {
				a.Client.Send(protocol.New("ddns.changes", "", 0, protocol.DDNSChanges{Changes: changes}), true)
			}
		}
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
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached, RecheckMaterial: true})
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
