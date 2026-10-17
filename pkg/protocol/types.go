// Package protocol exposes the versioned master/agent contract to master implementations.
package protocol

import (
	"github.com/VanSail-Opensource/X-Node/internal/config"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"net/netip"
)

const Version = wire.Version
const MaxFrameBytes = wire.MaxFrameBytes

type Message = wire.Message
type Config = wire.Config
type User = wire.User
type UserControl = wire.UserControl
type UserControls = wire.UserControls
type UsersSync = wire.UsersSync
type UsersDelta = wire.UsersDelta
type Provider = wire.Provider
type Certificate = wire.Certificate
type CertConfig = config.CertConfig
type DDNSJob = wire.DDNSJob
type DNSPolicy = wire.DNSPolicy
type PortRange = wire.PortRange
type FirewallPolicy = wire.FirewallPolicy
type FirewallRule = wire.FirewallRule
type FirewallBan = wire.FirewallBan
type FirewallExemption = wire.FirewallExemption
type FirewallSource = wire.FirewallSource
type FirewallEvent = wire.FirewallEvent
type FirewallEvents = wire.FirewallEvents
type FirewallEventAck = wire.FirewallEventAck
type FirewallUpdate = wire.FirewallUpdate
type FirewallState = wire.FirewallState

func FirewallPrefix(raw string) (netip.Prefix, error) { return wire.FirewallPrefix(raw) }
func FirewallRuleNames() []string                     { return append([]string(nil), wire.FirewallRuleNames...) }

type Forward = wire.Forward
type UpdatePolicy = wire.UpdatePolicy
type TelemetryPolicy = wire.TelemetryPolicy
type TorrentPolicy = wire.TorrentPolicy
type IPControl = wire.IPControl
type IPBlock = wire.IPBlock
type Traffic = wire.Traffic
type TrafficSample = wire.TrafficSample
type TrafficReport = wire.TrafficReport
type TrafficFlush = wire.TrafficFlush
type TrafficBarrier = wire.TrafficBarrier
type UserRate = wire.UserRate
type AgentHello = wire.AgentHello
type UserMetrics = wire.UserMetrics
type UserLimitStatus = wire.UserLimitStatus
type UserSpeedStatus = wire.UserSpeedStatus
type TelemetryReport = wire.TelemetryReport
