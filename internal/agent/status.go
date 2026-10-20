package agent

import (
	"context"
	"encoding/json"
	"fmt"
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
