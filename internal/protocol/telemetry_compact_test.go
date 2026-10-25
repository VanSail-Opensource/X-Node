package protocol

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestCompactTelemetryPreservesObservationsAndClearsInactiveUsers(t *testing.T) {
	report := TelemetryReport{AgentID: "agent", BootID: "boot", Ready: true, Users: UserMetrics{
		Connections: map[int]int{1: 3}, ActiveIPs: map[int][]string{1: {"8.8.8.8"}}, Rejections: map[string]uint64{"blocked": 17},
		Status: map[int]UserLimitStatus{1: {UserID: 1, Scope: "new_connection"}, 2: {UserID: 2, Scope: "new_connection"}, 3: {UserID: 3, Limited: true, Reason: "expired", Scope: "new_connection"}, 4: {UserID: 4, Limited: true, Reason: "active_ip_limit", Scope: "new_ip"}},
		Speed:  map[int]UserSpeedStatus{1: {NormalMbps: 10, BurstMbps: 20, ActiveMbps: 20}, 2: {}},
		Rates:  map[int]UserRate{1: {UploadBytesPerSecond: 123.5, DownloadBytesPerSecond: 456.25, SampleSeconds: 2}, 2: {SampleSeconds: 1}},
	}}
	compact := CompactTelemetry(report)
	if len(compact.Users) != 3 || compact.Users[0].ID != 1 || compact.Users[1].ID != 3 || compact.Users[2].ID != 4 {
		t.Fatal("default rows were retained or active rows lost", compact.Users)
	}
	decoded, err := ExpandTelemetry(compact)
	if err != nil || decoded.Users.Connections[1] != 3 || decoded.Users.Rates[1] != report.Users.Rates[1] || decoded.Users.Speed[1] != report.Users.Speed[1] || decoded.Users.Status[3] != report.Users.Status[3] || decoded.Users.Status[4] != report.Users.Status[4] || decoded.Users.Rejections["blocked"] != 17 || len(decoded.Users.ActiveIPs[1]) != 1 {
		t.Fatal("compact observations changed", decoded, err)
	}
	empty := CompactTelemetry(TelemetryReport{AgentID: "agent", BootID: "boot"})
	raw, err := json.Marshal(empty)
	if err != nil || strings.Contains(string(raw), `"p"`) || !strings.Contains(string(raw), `"u":[]`) {
		t.Fatal("empty snapshot or IP opt-in changed", string(raw), err)
	}
	decoded, err = ExpandTelemetry(empty)
	if err != nil || len(decoded.Users.Connections)+len(decoded.Users.Rates)+len(decoded.Users.Status)+len(decoded.Users.Speed)+len(decoded.Users.ActiveIPs) != 0 {
		t.Fatal("empty report retained old user observations", decoded, err)
	}
}

func TestCompactTelemetryRejectsMissingDuplicateAndInvalidMetrics(t *testing.T) {
	if _, err := ExpandTelemetry(CompactTelemetryReport{}); err == nil {
		t.Fatal("implicit snapshot accepted")
	}
	for _, rows := range [][]CompactUserMetrics{
		{{ID: 0}}, {{ID: 1}, {ID: 1}}, {{ID: 1, Connections: -1}},
		{{ID: 1, Rate: &CompactUserRate{Seconds: 0}}}, {{ID: 1, Rate: &CompactUserRate{Seconds: 1, Upload: math.Inf(1)}}},
		{{ID: 1, Speed: &CompactUserSpeed{NormalMbps: -1}}},
	} {
		if _, err := ExpandTelemetry(CompactTelemetryReport{Users: rows}); err == nil {
			t.Fatal("invalid compact metrics accepted", rows)
		}
	}
}

func TestPayloadExpansionBoundPrecedesDecoding(t *testing.T) {
	if _, err := ReadMessagePayload(strings.NewReader(strings.Repeat("x", MaxFrameBytes+1))); err == nil {
		t.Fatal("oversized expansion accepted")
	}
	data, err := ReadMessagePayload(strings.NewReader(`{"v":1,"type":"state.request"}`))
	if err != nil || len(data) == 0 {
		t.Fatal("small uncompressed fallback failed", err)
	}
}
