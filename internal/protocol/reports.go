package protocol

import (
	"encoding/json"
	"time"
)

type AgentHello struct {
	AgentID        string   `json:"agent_id"`
	BootID         string   `json:"boot_id"`
	Version        string   `json:"version"`
	XrayVersion    string   `json:"xray_version"`
	ConfigRevision uint64   `json:"config_revision"`
	Ready          bool     `json:"ready"`
	Capabilities   []string `json:"capabilities"`
	UpgradePending bool     `json:"upgrade_pending,omitempty"`
	BinarySHA256   string   `json:"binary_sha256,omitempty"`
	Platform       string   `json:"platform,omitempty"`
}

type UserLimitStatus struct {
	UserID  int    `json:"user_id"`
	Limited bool   `json:"limited"`
	Reason  string `json:"reason,omitempty"`
	Scope   string `json:"scope"`
}

type UserSpeedStatus struct {
	NormalMbps int  `json:"normal_mbps"`
	BurstMbps  int  `json:"burst_mbps"`
	Limited    bool `json:"limited"`
	ActiveMbps int  `json:"active_mbps"`
}

type UserMetrics struct {
	Connections map[int]int             `json:"connections"`
	ActiveIPs   map[int][]string        `json:"active_ips,omitempty"`
	Rejections  map[string]uint64       `json:"rejections"`
	Status      map[int]UserLimitStatus `json:"status"`
	Speed       map[int]UserSpeedStatus `json:"speed"`
	Rates       map[int]UserRate        `json:"rates,omitempty"`
}

type TelemetryReport struct {
	AgentID          string          `json:"agent_id"`
	BootID           string          `json:"boot_id"`
	Time             time.Time       `json:"time"`
	Connected        bool            `json:"connected"`
	Liveness         bool            `json:"liveness"`
	Ready            bool            `json:"ready"`
	Synchronized     bool            `json:"synchronized"`
	ConfigRevision   uint64          `json:"config_revision"`
	Users            UserMetrics     `json:"users"`
	Machine          json.RawMessage `json:"machine"`
	Certificates     json.RawMessage `json:"certificates"`
	TransportDropped uint64          `json:"transport_dropped"`
}
