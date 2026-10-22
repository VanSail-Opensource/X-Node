package protocol

// ActionEffect declares the consumer of each typed command. Unknown commands
// remain conservative; the command dispatcher still rejects unsupported names.
type ActionEffect uint8

const (
	ReconcileAction ActionEffect = iota
	ObserveAction
	RegistryAction
	FirewallAction
	UtilityAction
	ValidateAction
	ReloadAction
	UpgradeAction
)

var actionEffects = map[string]ActionEffect{
	"firewall.protected.sync": FirewallAction,
	"firewall.geoip.sync":     FirewallAction, "firewall.bans.sync": FirewallAction,
	"firewall.bans.update": FirewallAction, "firewall.bans.get": ObserveAction,
	"firewall.status": ObserveAction, "firewall.confirm": FirewallAction, "firewall.apply": FirewallAction,
	"connections.list": ObserveAction, "connections.close": RegistryAction,
	"users.active_ips": ObserveAction, "ips.control": RegistryAction,
	"metrics.get": ObserveAction, "jobs.list": ObserveAction, "certificates.get": ObserveAction,
	"traffic.flush": RegistryAction, "config.validate": ValidateAction,
	"speedtest": UtilityAction, "ddns.run": UtilityAction, "update.check": UtilityAction,
	"update.status": ObserveAction, "update.install": UpgradeAction, "update.rollback": UpgradeAction,
	"runtime.reload": ReloadAction, "geodata.refresh": ReloadAction,
}

func ClassifyAction(name string) ActionEffect { return actionEffects[name] }
