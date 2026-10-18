package protocol

import "time"

// CommandTimeout bounds execution after acceptance. Delivery is independently
// bounded to 30 seconds by the master, and must not consume the execution time.
func CommandTimeout(name string) time.Duration {
	switch name {
	case "update.install", "firewall.bans.sync", "firewall.geoip.sync":
		return 10 * time.Minute
	case "geodata.refresh", "firewall.apply":
		return 5 * time.Minute
	case "runtime.reload", "config.validate", "update.check", "traffic.flush":
		return 2 * time.Minute
	case "speedtest":
		return 90 * time.Second
	default:
		return 30 * time.Second
	}
}
