package protocol

import (
	"errors"
	"math"
)

func ExpandTelemetry(compact CompactTelemetryReport) (TelemetryReport, error) {
	report := TelemetryReport{AgentID: compact.AgentID, BootID: compact.BootID, Time: compact.Time, Connected: compact.Connected, Liveness: compact.Liveness, Ready: compact.Ready, Synchronized: compact.Synchronized, ConfigRevision: compact.ConfigRevision, Machine: compact.Machine, Certificates: compact.Certificates, TransportDropped: compact.TransportDropped}
	if compact.Users == nil {
		return report, errors.New("compact telemetry requires an explicit user snapshot")
	}
	report.Users = UserMetrics{Connections: map[int]int{}, TotalConnections: map[int]int{}, ActiveIPs: map[int][]string{}, Rejections: compact.Rejections, Status: map[int]UserLimitStatus{}, Speed: map[int]UserSpeedStatus{}, Rates: map[int]UserRate{}}
	seen := make(map[int]bool, len(compact.Users))
	for _, row := range compact.Users {
		if row.ID <= 0 || seen[row.ID] || row.Connections < 0 || row.TotalConnections < 0 {
			return report, errors.New("invalid compact telemetry user")
		}
		seen[row.ID] = true
		if row.Connections != 0 {
			report.Users.Connections[row.ID] = row.Connections
		}
		if row.TotalConnections != 0 {
			report.Users.TotalConnections[row.ID] = row.TotalConnections
		}
		if len(row.IPs) != 0 {
			report.Users.ActiveIPs[row.ID] = row.IPs
		}
		if row.Limited || row.Reason != "" || row.Scope != "" {
			scope := row.Scope
			if scope == "" {
				scope = "new_connection"
			}
			report.Users.Status[row.ID] = UserLimitStatus{UserID: row.ID, Limited: row.Limited, Reason: row.Reason, Scope: scope}
		}
		if speed := row.Speed; speed != nil {
			if speed.NormalMbps < 0 || speed.BurstMbps < 0 || speed.ActiveMbps < 0 {
				return report, errors.New("invalid compact telemetry speed")
			}
			report.Users.Speed[row.ID] = UserSpeedStatus{NormalMbps: speed.NormalMbps, BurstMbps: speed.BurstMbps, Limited: speed.Limited, ActiveMbps: speed.ActiveMbps}
		}
		if rate := row.Rate; rate != nil {
			if !finiteRate(rate.Upload) || !finiteRate(rate.Download) || rate.Seconds <= 0 || math.IsNaN(rate.Seconds) || math.IsInf(rate.Seconds, 0) {
				return report, errors.New("invalid compact telemetry rate")
			}
			report.Users.Rates[row.ID] = UserRate{UploadBytesPerSecond: rate.Upload, DownloadBytesPerSecond: rate.Download, SampleSeconds: rate.Seconds}
		}
	}
	return report, nil
}

func finiteRate(value float64) bool { return value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) }
