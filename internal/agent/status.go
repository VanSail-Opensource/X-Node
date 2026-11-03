package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net"
	"os"
	"time"
)

func (a *Agent) sendStatus() {
	a.requestReports(reportStatus)
}

func (a *Agent) publishStatus() {
	d := a.Store.Metadata()
	summary := a.Registry.Summary()
	if d != a.Store.Metadata() {
		a.sendStatus()
		return
	}
	synchronized := d.HasConfig && d.ConfigRevision == d.Revision && !a.applying.Load()
	report := protocol.TelemetryReport{AgentID: d.AgentID, BootID: a.BootID, Time: time.Now().UTC(), Connected: a.Client.Connected(), Liveness: true, Ready: a.Runtime.Ready(), Synchronized: synchronized, ConfigRevision: d.ConfigRevision, Users: summary, Machine: telemetryJSON(a.Sampler.Snapshot()), Certificates: telemetryJSON(a.Certificates.Status()), TransportDropped: a.Client.Dropped()}
	var message protocol.Message
	if a.Client.CompactTelemetry() {
		message = protocol.New("telemetry.compact", "", d.Revision, protocol.CompactTelemetry(report))
	} else {
		message = protocol.New("telemetry.report", "", d.Revision, report)
	}
	a.Client.Send(message, false)
	notifySystemd(fmt.Sprintf("STATUS=Runtime ready=%t synchronized=%t connected=%t authorization=%d configuration=%d", a.Runtime.Ready(), synchronized, a.Client.Connected(), d.Revision, d.ConfigRevision))
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
	if (!a.Runtime.Ready() || !a.retryAt.IsZero()) && !a.applying.Load() && !now.Before(a.retryAt) {
		d := a.Store.Metadata()
		a.queue(ctx, applyJob{Revision: d.Revision, Config: a.desired, Cached: a.desiredCached})
	}
	if !a.applying.Load() && a.Certificates.Renewed() {
		d := a.Store.Metadata()
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
