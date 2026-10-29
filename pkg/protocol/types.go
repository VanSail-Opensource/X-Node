// Package protocol exposes the versioned master/agent contract to master implementations.
package protocol

import (
	"github.com/VanSail-Opensource/X-Node/internal/config"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"io"
	"net/netip"
)

const Version = wire.Version
const MaxFrameBytes = wire.MaxFrameBytes
const MaxFirewallEventsPerFrame = wire.MaxFirewallEventsPerFrame
const GeoIPPrefixesPerChunk = wire.GeoIPPrefixesPerChunk
const BuiltinDDNSProvider = wire.BuiltinDDNSProvider
const BuiltinDDNSCapability = wire.BuiltinDDNSCapability
const DDNSChangesCapability = wire.DDNSChangesCapability
const DDNSChangesHeader = wire.DDNSChangesHeader
const DDNSChangesFormat = wire.DDNSChangesFormat
const MaxDDNSChangesPerFrame = wire.MaxDDNSChangesPerFrame

type DDNSChange = wire.DDNSChange
type DDNSChanges = wire.DDNSChanges
type DDNSChangeAck = wire.DDNSChangeAck

type Message = wire.Message
type Config = wire.Config
type Changes = wire.Changes

func Classify(old, next Config) Changes { return wire.Classify(old, next) }
func NativeIdentity(c Config) []byte    { return wire.NativeIdentity(c) }

type User = wire.User
type TransitCredential = wire.TransitCredential
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
type GeoIPChunk = wire.GeoIPChunk
type SourceGeoIPPolicy = wire.SourceGeoIPPolicy
type SourceGeoIPListener = wire.SourceGeoIPListener
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
type CompactTelemetryReport = wire.CompactTelemetryReport
type CompactUserMetrics = wire.CompactUserMetrics
type CompactUserSpeed = wire.CompactUserSpeed
type CompactUserRate = wire.CompactUserRate

const CompactTelemetryCapability = wire.CompactTelemetryCapability
const OpenConnectionsCapability = wire.OpenConnectionsCapability
const OpenConnectionsHeader = wire.OpenConnectionsHeader
const OpenConnectionsFormat = wire.OpenConnectionsFormat
const TelemetryFormatHeader = wire.TelemetryFormatHeader
const CompactTelemetryFormat = wire.CompactTelemetryFormat

func CompactTelemetry(report TelemetryReport) CompactTelemetryReport {
	return wire.CompactTelemetry(report)
}
func ExpandTelemetry(report CompactTelemetryReport) (TelemetryReport, error) {
	return wire.ExpandTelemetry(report)
}
func ReadMessagePayload(reader io.Reader) ([]byte, error) { return wire.ReadMessagePayload(reader) }

func ExemptionPrefix(raw string) (netip.Prefix, error) { return wire.ExemptionPrefix(raw) }
func ExemptionKey(raw string) (string, error)          { return wire.ExemptionKey(raw) }

// RuntimeReloadArgs selects incremental material recheck or explicit recovery.
type RuntimeReloadArgs = wire.RuntimeReloadArgs
