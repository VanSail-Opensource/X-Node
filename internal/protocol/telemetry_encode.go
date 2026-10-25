package protocol

import "slices"

func CompactTelemetry(report TelemetryReport) CompactTelemetryReport {
	compact := CompactTelemetryReport{AgentID: report.AgentID, BootID: report.BootID, Time: report.Time, Connected: report.Connected, Liveness: report.Liveness, Ready: report.Ready, Synchronized: report.Synchronized, ConfigRevision: report.ConfigRevision, Users: []CompactUserMetrics{}, Rejections: report.Users.Rejections, Machine: report.Machine, Certificates: report.Certificates, TransportDropped: report.TransportDropped}
	ids := map[int]bool{}
	for id := range report.Users.Connections {
		ids[id] = true
	}
	for id := range report.Users.ActiveIPs {
		ids[id] = true
	}
	for id := range report.Users.Status {
		ids[id] = true
	}
	for id := range report.Users.Speed {
		ids[id] = true
	}
	for id := range report.Users.Rates {
		ids[id] = true
	}
	for id := range ids {
		row := CompactUserMetrics{ID: id, Connections: report.Users.Connections[id], IPs: report.Users.ActiveIPs[id]}
		status := report.Users.Status[id]
		if status.Limited || status.Reason != "" {
			row.Limited, row.Reason = status.Limited, status.Reason
			if status.Scope != "new_connection" {
				row.Scope = status.Scope
			}
		}
		if speed := report.Users.Speed[id]; speed != (UserSpeedStatus{}) {
			row.Speed = &CompactUserSpeed{NormalMbps: speed.NormalMbps, BurstMbps: speed.BurstMbps, Limited: speed.Limited, ActiveMbps: speed.ActiveMbps}
		}
		if rate, exists := report.Users.Rates[id]; exists && (rate.UploadBytesPerSecond != 0 || rate.DownloadBytesPerSecond != 0 || rate.SampleSeconds <= 0) {
			row.Rate = &CompactUserRate{Upload: rate.UploadBytesPerSecond, Download: rate.DownloadBytesPerSecond, Seconds: rate.SampleSeconds}
		}
		if row.Connections != 0 || len(row.IPs) != 0 || row.Limited || row.Reason != "" || row.Speed != nil || row.Rate != nil {
			compact.Users = append(compact.Users, row)
		}
	}
	slices.SortFunc(compact.Users, func(a, b CompactUserMetrics) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return compact
}
