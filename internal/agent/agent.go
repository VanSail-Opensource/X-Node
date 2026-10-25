// Package agent serializes authoritative state while utility work runs independently.
package agent

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/cert"
	"github.com/VanSail-Opensource/X-Node/internal/firewall"
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
	"github.com/xtls/xray-core/core"
)

type applyJob struct {
	Done            chan error
	ForceRebuild    bool
	RefreshAssets   bool
	RecheckMaterial bool
	ID              string
	Revision        uint64
	Config          protocol.Config
	Cached          bool
	Context         context.Context
	Generation      uint64
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
	Guard               *firewall.Guard
	Dir                 string
	Version             string
	BootID              string
	Store               *state.Store
	Registry            *sessions.Registry
	Runtime             *xray.Runtime
	Client              *transport.Client
	Logs                *nlog.Stream
	Sampler             *monitor.Sampler
	Certificates        *cert.Pool
	Firewall            *firewall.Manager
	Updater             *updatepkg.Manager
	Runner              host.Runner
	Jobs                *Jobs
	ddnsJournal         *state.DDNSJournal
	desired             protocol.Config
	desiredCached       bool
	hasDesired          bool
	apply               chan applyJob
	applied             chan applied
	cancelApply         context.CancelFunc
	applying            atomic.Bool
	materialPending     bool // actor-owned until the latest activation succeeds
	bans                chan banEvent
	previous            state.Traffic
	previousAccounting  map[string][2]uint64
	lastCapture         time.Time
	accountingRequests  chan accountingRequest
	lastReport          time.Time
	lastDDNS            map[string]time.Time
	lastUpdate          time.Time
	geoNext             atomic.Int64
	geoFailures         int
	geoPolicy           string
	geoRunning          atomic.Bool
	notify              chan reloadRequest
	reloadDone          chan error
	generation          uint64
	nativeMu            sync.Mutex
	nativePrepared      *xray.Prepared
	validationKey       [32]byte
	validationValid     bool
	firewallInitialized bool
	geoCandidate        string
	geoCandidateKey     string
	geoMu               sync.Mutex
	dnsMu               sync.Mutex
	utilityCancel       context.CancelFunc
	utilityContext      context.Context
	retryAt             time.Time
	retryDelay          time.Duration
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
	a.ddnsJournal, e = state.OpenDDNS(dir)
	if e != nil {
		nlog.Core().Warn("DDNS journal unavailable")
	}
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
		return protocol.New("agent.hello", "", d.Revision, map[string]any{"agent_id": d.AgentID, "boot_id": a.BootID, "version": version, "xray_version": "v" + core.Version(), "config_revision": d.ConfigRevision, "ready": a.Runtime.Ready(), "capabilities": Capabilities, "upgrade_pending": a.Updater.Pending(), "binary_sha256": metadata.SHA256, "platform": metadata.Platform})
	}
	return a, nil
}

var Capabilities = []string{protocol.BuiltinDDNSCapability, protocol.DDNSChangesCapability, protocol.CompactTelemetryCapability, "incremental_reload_v1", "member_source_whitelist_v1", "firewall_master_observation_v1", "telegram_identity_rekey_v1", "native_hot_reload_v1", "activation_commands_v1", "update_transaction_v1", "firewall_cidr_exemptions_v1", "source_geoip_stream_v1", "disk_firewall_sources_v1", "node_file_certificates_v1", "xtables_compat_snapshot_v1", "host_firewall_ownership_v1", "sampled_activity_v1", "transit_credentials_v1", "source_geoip_firewall_v1", "shared_domain_blocks_v1", "geodata_interval_v1", "native_firewall_v1", "firewall_control_v1", "native_xray", "multi_inbound", "tcp_udp_limits", "session_revocation", "traffic_ack", "certificates", "ddns", "xray_scoped_dns_v1", "geodata", "nftables", "port_forward", "metrics", "logs", "peer_speedtest", "torrent_ban", "signed_updates", "traffic_periods_v1", "measured_user_rates", "authorization_expiry", "member_outbound_guards", "traffic_period_barriers_v1", "config_validation_v1", "volatile_connection_controls_v1", "native_auxiliary_inbounds_v1"}
