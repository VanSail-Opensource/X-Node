package firewall

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"strconv"
	"time"
)

// GuardStatus contains only a current operational projection. Command history
// must not persist this live information.
type GuardStatus = protocol.FirewallState

func (g *Guard) Status() GuardStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.statusLocked()
}
func (g *Guard) statusLocked() GuardStatus {
	result := GuardStatus{SourceVersion: g.state.SourceMasterVersion, MasterVersion: g.state.MasterVersion, InstanceID: g.state.EventNamespace, SnapshotID: g.state.SnapshotID, SourceGenerations: map[string]string{}, ErrorCode: g.kernelError, KernelReady: g.kernelReady.Load(), PendingReports: len(g.state.Events), Dropped: strconv.FormatUint(g.dropped.Load(), 10)}
	if policy := g.policy.Load(); policy != nil {
		result.Enabled = policy.Enabled
		result.DetectionEnabled = policy.Enabled && policy.Protect && policy.MasterControlled
	}
	if result.DetectionEnabled && !result.KernelReady && result.ErrorCode == "" {
		result.ErrorCode = "FIREWALL_DETECTION_UNAVAILABLE"
	}
	now := time.Now()
	for _, ban := range g.state.Bans {
		if ban.Until.After(now) {
			result.ActiveBans++
		}
	}
	for id, source := range g.state.Sources {
		if source.Until.After(now) && !source.Expired {
			result.SourceGenerations[id] = source.Generation
		}
		if source.Until.After(now) && !source.Expired {
			result.Sources++
			result.SourcePrefixes += source.PrefixCount
		}
	}
	for _, exemption := range g.state.Exemptions {
		if exemption.Until.After(now) {
			result.Exemptions++
		}
	}
	return result
}
