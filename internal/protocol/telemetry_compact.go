package protocol

import (
	"encoding/json"
	"time"
)

const CompactTelemetryCapability = "compact_telemetry_v1"
const TelemetryFormatHeader = "X-XNode-Telemetry"
const CompactTelemetryFormat = "compact-v1"

// CompactTelemetryReport remains an authoritative snapshot. Empty users clears
// every previous online/rate/limit observation; omitted fields mean zero/default.
type CompactTelemetryReport struct {
	AgentID          string               `json:"a"`
	BootID           string               `json:"b"`
	Time             time.Time            `json:"t"`
	Connected        bool                 `json:"c,omitempty"`
	Liveness         bool                 `json:"l,omitempty"`
	Ready            bool                 `json:"r,omitempty"`
	Synchronized     bool                 `json:"s,omitempty"`
	ConfigRevision   uint64               `json:"v,omitempty"`
	Users            []CompactUserMetrics `json:"u"`
	Rejections       map[string]uint64    `json:"x,omitempty"`
	Machine          json.RawMessage      `json:"m,omitempty"`
	Certificates     json.RawMessage      `json:"k,omitempty"`
	TransportDropped uint64               `json:"d,omitempty"`
}

type CompactUserMetrics struct {
	ID               int               `json:"i"`
	Connections      int               `json:"c,omitempty"`
	TotalConnections int               `json:"o,omitempty"`
	IPs              []string          `json:"p,omitempty"`
	Limited          bool              `json:"l,omitempty"`
	Reason           string            `json:"r,omitempty"`
	Scope            string            `json:"s,omitempty"`
	Speed            *CompactUserSpeed `json:"x,omitempty"`
	Rate             *CompactUserRate  `json:"b,omitempty"`
}

type CompactUserSpeed struct {
	NormalMbps int  `json:"n,omitempty"`
	BurstMbps  int  `json:"b,omitempty"`
	Limited    bool `json:"l,omitempty"`
	ActiveMbps int  `json:"a,omitempty"`
}

type CompactUserRate struct {
	Upload   float64 `json:"u,omitempty"`
	Download float64 `json:"d,omitempty"`
	Seconds  float64 `json:"s"`
}
