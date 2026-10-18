// Package protocol defines the master/agent WebSocket v1 contract.
package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/config"
)

const Version = 1
const MaxFrameBytes = 16 << 20

type Message struct {
	V            int             `json:"v"`
	Type         string          `json:"type"`
	ID           string          `json:"id,omitempty"`
	Revision     uint64          `json:"revision,omitempty"`
	BaseRevision uint64          `json:"base_revision,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

func New(typ, id string, revision uint64, data any) Message {
	b, _ := json.Marshal(data)
	return Message{V: Version, Type: typ, ID: id, Revision: revision, Data: b}
}

func Decode(b []byte, out any) error {
	if len(b) == 0 || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return errors.New("missing or null payload")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid payload shape")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func Parse(b []byte) (Message, error) {
	var m Message
	if len(b) > MaxFrameBytes {
		return m, errors.New("frame too large")
	}
	if err := Decode(b, &m); err != nil {
		return m, err
	}
	if m.V != Version || m.Type == "" || len(m.Type) > 64 || len(m.ID) > 128 {
		return m, errors.New("unsupported envelope")
	}
	return m, nil
}

type User struct {
	ID   int    `json:"id"`
	UUID string `json:"uuid,omitempty"`
	// Native client/account properties, keyed by inbound tag. Email and level are managed.
	Credentials            map[string]json.RawMessage `json:"credentials,omitempty"`
	TransitCredentials     []TransitCredential        `json:"transit_credentials,omitempty"`
	InboundTags            []string                   `json:"inbound_tags"`
	ActiveIPLimit          int                        `json:"active_ip_limit,omitempty"`
	ConnectionLimit        int                        `json:"connection_limit,omitempty"`
	SpeedLimitMbps         int                        `json:"speed_limit_mbps,omitempty"`
	BurstSpeedLimitMbps    int                        `json:"burst_speed_limit_mbps,omitempty"`
	SpeedLimitAfterSeconds int                        `json:"speed_limit_after_seconds,omitempty"`
	SpeedLimitResetSeconds int                        `json:"speed_limit_reset_seconds,omitempty"`
	BlockNew               bool                       `json:"block_new,omitempty"`
	AccountingPeriod       string                     `json:"accounting_period,omitempty"`
	ValidUntil             *time.Time                 `json:"valid_until,omitempty"`
}

// UserEmail binds authenticated transports to the current credential generation.
// A revoked mux transport cannot authenticate new leaf streams using only a stable user ID.
func UserEmail(u User, tag string) string {
	var credential any = u.UUID
	if raw := u.Credentials[tag]; len(raw) > 0 {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		delete(m, "email")
		delete(m, "level")
		credential = m
	}
	b, _ := json.Marshal(credential)
	h := sha256.Sum256(b)
	return fmt.Sprintf("user@%d:%s", u.ID, hex.EncodeToString(h[:16]))
}

type UsersSync struct {
	Users *[]User `json:"users"`
}
type UsersDelta struct {
	Upsert []User `json:"upsert,omitempty"`
	Remove []int  `json:"remove,omitempty"`
}
type UserControl struct {
	ID       int  `json:"id"`
	BlockNew bool `json:"block_new"`
}

func (u *UserControl) UnmarshalJSON(b []byte) error {
	var v struct {
		ID       int   `json:"id"`
		BlockNew *bool `json:"block_new"`
	}
	if e := Decode(b, &v); e != nil {
		return e
	}
	if v.ID <= 0 || v.BlockNew == nil {
		return errors.New("user control requires id and block_new")
	}
	u.ID = v.ID
	u.BlockNew = *v.BlockNew
	return nil
}

type UserControls struct {
	Users []UserControl `json:"users"`
}

type Provider struct {
	Type        string            `json:"type"`
	Credentials map[string]string `json:"credentials"`
}
type Certificate struct {
	Provider string            `json:"provider,omitempty"`
	Config   config.CertConfig `json:"config"`
}
type DDNSJob struct {
	ID              string `json:"id"`
	Provider        string `json:"provider"`
	Zone            string `json:"zone"`
	Name            string `json:"name"`
	IPv4            string `json:"ipv4,omitempty"`
	IPv6            string `json:"ipv6,omitempty"`
	Interface       string `json:"interface,omitempty"`
	IPv4URL         string `json:"ipv4_url,omitempty"`
	IPv6URL         string `json:"ipv6_url,omitempty"`
	TTLSeconds      int    `json:"ttl_seconds,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}
type DNSPolicy struct {
	Mode      string   `json:"mode,omitempty"`
	Redirect  bool     `json:"redirect,omitempty"`
	Upstreams []string `json:"upstreams,omitempty"`
}
type PortRange struct {
	From    int    `json:"from"`
	To      int    `json:"to"`
	Network string `json:"network,omitempty"`
}
type Forward struct {
	ListenIP   string `json:"listen_ip,omitempty"`
	Port       int    `json:"port"`
	TargetIP   string `json:"target_ip"`
	TargetPort int    `json:"target_port"`
	Network    string `json:"network"`
}
type FirewallPolicy struct {
	SourceGeoIP      *SourceGeoIPPolicy      `json:"source_geoip,omitempty"`
	MasterControlled bool                    `json:"master_controlled,omitempty"`
	Rules            map[string]FirewallRule `json:"rules,omitempty"`
	BanSeconds       int                     `json:"ban_seconds,omitempty"`
	Enabled          bool                    `json:"enabled"`
	Protect          bool                    `json:"protect"`
	TCPPorts         []int                   `json:"tcp_ports,omitempty"`
	UDPPorts         []int                   `json:"udp_ports,omitempty"`
	SSHPorts         []int                   `json:"ssh_ports,omitempty"`
	AllowPrefixes    []string                `json:"allow_prefixes,omitempty"`
	Forward          []Forward               `json:"forward,omitempty"`
}
type UpdatePolicy struct {
	Enabled bool   `json:"enabled"`
	Version string `json:"version,omitempty"`
}
type TelemetryPolicy struct {
	IncludeActiveIPs bool `json:"include_active_ips,omitempty"`
	SampleSeconds    int  `json:"sample_seconds,omitempty"`
	ReportSeconds    int  `json:"report_seconds,omitempty"`
}
type IPControl struct {
	SourceIP     string `json:"source_ip"`
	UserID       int    `json:"user_id,omitempty"`
	Drop         bool   `json:"drop,omitempty"`
	BlockSeconds int    `json:"block_seconds,omitempty"`
	Unblock      bool   `json:"unblock,omitempty"`
}
type IPBlock struct {
	SourceIP string    `json:"source_ip"`
	UserID   int       `json:"user_id,omitempty"`
	Until    time.Time `json:"until"`
}
type TorrentPolicy struct {
	Enabled    bool `json:"enabled"`
	BanSeconds int  `json:"ban_seconds,omitempty"`
}

type Config struct {
	BlockedDomains      []string               `json:"blocked_domains,omitempty"`
	Xray                json.RawMessage        `json:"xray"`
	Users               []User                 `json:"users"`
	Providers           map[string]Provider    `json:"providers,omitempty"`
	Certificates        map[string]Certificate `json:"certificates,omitempty"`
	InboundCertificates map[string]string      `json:"inbound_certificates,omitempty"`
	DDNS                []DDNSJob              `json:"ddns,omitempty"`
	DNS                 DNSPolicy              `json:"dns,omitempty"`
	Firewall            FirewallPolicy         `json:"firewall,omitempty"`
	BlockedPorts        []PortRange            `json:"blocked_ports,omitempty"`
	AssetHashes         map[string]string      `json:"asset_hashes,omitempty"`
	Updates             UpdatePolicy           `json:"updates,omitempty"`
	Telemetry           TelemetryPolicy        `json:"telemetry,omitempty"`
	Torrent             TorrentPolicy          `json:"torrent,omitempty"`
	MemberOutbounds     []string               `json:"member_outbounds,omitempty"`
}

func ParseConfig(b []byte) (Config, error) {
	var c Config
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return c, errors.New("invalid configuration")
	}
	raw := bytes.TrimSpace(fields["users"])
	if len(raw) == 0 || raw[0] != '[' {
		return c, errors.New("users must be an explicit array")
	}
	if err := Decode(b, &c); err != nil {
		return c, err
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	return c, nil
}

func ValidateUsers(users []User) error {
	if len(users) > 100000 {
		return errors.New("too many users")
	}
	ids := make(map[int]bool, len(users))
	accounts := make(map[string]bool)
	for _, u := range users {
		if err := validateTransit(u); err != nil {
			return err
		}
		if u.AccountingPeriod != "" && !ValidName(u.AccountingPeriod) || u.ValidUntil != nil && u.ValidUntil.IsZero() {
			return errors.New("invalid user accounting period or expiration")
		}
		if u.ID <= 0 || ids[u.ID] || u.ActiveIPLimit < 0 || u.ConnectionLimit < 0 || u.SpeedLimitMbps < 0 || u.SpeedLimitMbps > 1000000 || u.BurstSpeedLimitMbps < 0 || u.BurstSpeedLimitMbps > 1000000 || u.BurstSpeedLimitMbps > 0 && (u.SpeedLimitMbps == 0 || u.BurstSpeedLimitMbps < u.SpeedLimitMbps) || u.SpeedLimitAfterSeconds < 0 || u.SpeedLimitAfterSeconds > 3600 || u.SpeedLimitResetSeconds < 0 || u.SpeedLimitResetSeconds > 3600 {
			return errors.New("invalid or duplicate user")
		}
		ids[u.ID] = true
		if len(u.InboundTags) == 0 || (u.UUID == "" && len(u.Credentials) == 0) {
			return fmt.Errorf("user %d needs inbound tags and credentials", u.ID)
		}
		seen := map[string]bool{}
		for _, tag := range u.InboundTags {
			if !ValidName(tag) || seen[tag] {
				return errors.New("invalid or duplicate inbound tag")
			}
			seen[tag] = true
			raw := u.Credentials[tag]
			key := tag + ":" + u.UUID
			if len(raw) > 0 {
				var account map[string]any
				if json.Unmarshal(raw, &account) != nil || account == nil {
					return errors.New("invalid account object")
				}
				delete(account, "email")
				delete(account, "level")
				canonical, _ := json.Marshal(account)
				key = tag + ":" + string(canonical)
			}
			if accounts[key] {
				return errors.New("duplicate inbound credentials")
			}
			accounts[key] = true
		}
		for tag := range u.Credentials {
			if !seen[tag] {
				return errors.New("credentials reference an ineligible inbound")
			}
		}
		for _, binding := range u.TransitCredentials {
			var account map[string]any
			if err := json.Unmarshal(binding.Credential, &account); err != nil {
				return err
			}
			if id, ok := account["id"].(string); ok && strings.EqualFold(id, u.UUID) {
				return errors.New("transit credentials must be distinct")
			}
			canonical, _ := json.Marshal(account)
			key := binding.InboundTag + ":" + string(canonical)
			if accounts[key] {
				return errors.New("duplicate transit credentials")
			}
			accounts[key] = true
		}
	}
	return validateDistinctTransitAccounts(users)
}

func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.HasPrefix(s, "_xnode_") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return false
		}
	}
	return true
}

func (c Config) Validate() error {
	if err := ValidateNativePolicies(c); err != nil {
		return err
	}
	if err := c.Firewall.ValidateDetection(); err != nil {
		return err
	}
	if err := validateAuxiliaryUsers(c); err != nil {
		return err
	}
	if err := ValidateMemberOutbounds(c.Xray, c.MemberOutbounds); err != nil {
		return err
	}
	if err := ValidateUsers(c.Users); err != nil {
		return err
	}
	var native map[string]json.RawMessage
	if json.Unmarshal(c.Xray, &native) != nil || native == nil {
		return errors.New("xray must be an object")
	}
	if c.DNS.Mode != "" && c.DNS.Mode != "xray" && c.DNS.Mode != "smartdns" {
		return errors.New("unsupported resolver mode")
	}
	if c.DNS.Redirect && c.DNS.Mode != "smartdns" {
		var resolver struct {
			Servers []json.RawMessage `json:"servers"`
		}
		if json.Unmarshal(native["dns"], &resolver) != nil || len(resolver.Servers) == 0 {
			return errors.New("DNS interception requires explicit Xray DNS servers")
		}
	}
	if c.Telemetry.SampleSeconds < 0 || c.Telemetry.SampleSeconds > 3600 || c.Telemetry.ReportSeconds < 0 || c.Telemetry.ReportSeconds > 3600 || c.Torrent.BanSeconds < 0 || c.Torrent.BanSeconds > 604800 {
		return errors.New("invalid interval")
	}
	for _, ranges := range [][]PortRange{c.BlockedPorts} {
		for _, r := range ranges {
			if r.From < 1 || r.To < r.From || r.To > 65535 || r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
				return errors.New("invalid port range")
			}
		}
	}
	for _, ports := range [][]int{c.Firewall.TCPPorts, c.Firewall.UDPPorts, c.Firewall.SSHPorts} {
		for _, p := range ports {
			if p < 1 || p > 65535 {
				return errors.New("invalid firewall port")
			}
		}
	}
	for _, p := range c.Firewall.AllowPrefixes {
		if _, err := netip.ParsePrefix(p); err != nil {
			return errors.New("invalid allow prefix")
		}
	}
	for _, f := range c.Firewall.Forward {
		target, e := netip.ParseAddr(f.TargetIP)
		if e != nil || target.IsUnspecified() || target.IsMulticast() || f.Port < 1 || f.Port > 65535 || f.TargetPort < 1 || f.TargetPort > 65535 || f.Network != "tcp" && f.Network != "udp" {
			return errors.New("invalid forwarding rule")
		}
		if f.ListenIP != "" {
			l, e := netip.ParseAddr(f.ListenIP)
			if e != nil || l.Is4() != target.Is4() {
				return errors.New("forward address families differ")
			}
		}
	}
	for id, p := range c.Providers {
		if !ValidName(id) || p.Type == "" {
			return errors.New("invalid DNS provider")
		}
	}
	for id, p := range c.Certificates {
		if !ValidName(id) || p.Config.Domain == "" && p.Config.CertMode != "file" {
			return errors.New("invalid certificate profile")
		}
		if p.Config.CertMode == "file" && (p.Config.CertFile == "" || p.Config.KeyFile == "") {
			return errors.New("node-file certificates require certificate and key paths")
		}
		if p.Provider != "" {
			if _, ok := c.Providers[p.Provider]; !ok {
				return errors.New("unknown certificate provider")
			}
		}
	}
	for _, id := range c.InboundCertificates {
		if _, ok := c.Certificates[id]; !ok {
			return errors.New("unknown certificate profile")
		}
	}
	jobs := map[string]bool{}
	for _, j := range c.DDNS {
		if !ValidName(j.ID) || jobs[j.ID] || j.Zone == "" || j.Name == "" || j.IntervalSeconds < 0 || j.IntervalSeconds > 86400 || j.TTLSeconds < 0 {
			return errors.New("invalid DDNS job")
		}
		jobs[j.ID] = true
		if _, ok := c.Providers[j.Provider]; !ok {
			return errors.New("unknown DDNS provider")
		}
		for _, s := range []string{j.IPv4URL, j.IPv6URL} {
			if s != "" {
				u, e := url.Parse(s)
				if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
					return errors.New("DDNS lookup requires HTTPS")
				}
			}
		}
	}
	return nil
}

func uHost(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Hostname()
}

func Clone[T any](value T) T {
	b, _ := json.Marshal(value)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}
func (c Config) SampleInterval() time.Duration {
	if c.Telemetry.SampleSeconds == 0 {
		return time.Second
	}
	return time.Duration(c.Telemetry.SampleSeconds) * time.Second
}
func (c Config) ReportInterval() time.Duration {
	if c.Telemetry.ReportSeconds == 0 {
		return 5 * time.Second
	}
	return time.Duration(c.Telemetry.ReportSeconds) * time.Second
}
func (c Config) BanDuration() time.Duration {
	if c.Torrent.BanSeconds == 0 {
		return 10 * time.Minute
	}
	return time.Duration(c.Torrent.BanSeconds) * time.Second
}
