package agent

// Read-only session and metrics results are memory-only, including replay history.
func durableJobHistory(history []JobResult) []JobResult {
	out := make([]JobResult, 0, len(history))
	for _, result := range history {
		switch result.Command {
		case "connections.list", "users.active_ips", "metrics.get", "jobs.list":
			continue
		default:
			out = append(out, result)
		}
	}
	return out
}
