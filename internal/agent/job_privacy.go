package agent

import "github.com/VanSail-Opensource/X-Node/internal/protocol"

// Observation payloads and existing volatile connection controls never enter
// the journal. Their independent state/epoch policies remain authoritative.
func observationJob(command string) bool {
	switch protocol.ClassifyAction(command) {
	case protocol.ObserveAction, protocol.ValidateAction:
		return true
	}
	return command == "update.check" || command == "speedtest"
}

func persistentJob(command string) bool {
	if observationJob(command) {
		return false
	}
	switch command {
	case protocol.AutomaticLeaseCommand, "firewall.protected.sync", "ips.control", "connections.close":
		return false
	}
	return true
}

func durableJobHistory(history []JobResult) []JobResult {
	out := make([]JobResult, 0, len(history))
	for _, result := range history {
		if persistentJob(result.Command) {
			out = append(out, result)
		}
	}
	return out
}

func protectedJob(result JobResult) bool {
	return persistentJob(result.Command) && (result.Status == "uncertain" || result.Status == "running" || result.Status == "cancelled")
}
