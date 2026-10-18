package protocol

import (
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

// SourceGeoIPPolicy contains master-resolved prefixes, never a GeoIP selector or URL.
type SourceGeoIPPolicy struct {
	Generation string                `json:"generation"`
	Prefixes   []string              `json:"prefixes,omitempty"`
	Reference  bool                  `json:"reference,omitempty"`
	Listeners  []SourceGeoIPListener `json:"listeners"`
}

type SourceGeoIPListener struct {
	ListenIP string `json:"listen_ip,omitempty"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
}

// ValidateNativePolicies applies to the public validator and agent activation.
func ValidateNativePolicies(config Config) error {
	if len(config.BlockedDomains) > 10000 {
		return errors.New("too many blocked domain selectors")
	}
	for _, domain := range config.BlockedDomains {
		if len(domain) == 0 || len(domain) > 1024 || strings.ContainsAny(domain, "\x00\r\n") {
			return errors.New("invalid blocked domain selector")
		}
		if pattern, ok := strings.CutPrefix(domain, "regexp:"); ok {
			if _, err := regexp.Compile(pattern); err != nil {
				return errors.New("invalid blocked domain expression")
			}
		}
		if strings.HasPrefix(domain, "ext:") || strings.HasPrefix(domain, "geoip:") {
			return errors.New("external or IP domain selectors are not supported")
		}
	}
	var native any
	if json.Unmarshal(config.Xray, &native) != nil {
		return errors.New("invalid Xray document")
	}
	if containsGeoIP(native, "") {
		return errors.New("GeoIP routing and DNS selectors must not be sent to agents; use the master source-IP firewall policy")
	}
	var assets struct {
		Geodata struct {
			Assets []struct {
				File string `json:"file"`
			} `json:"assets"`
		} `json:"geodata"`
	}
	if json.Unmarshal(config.Xray, &assets) != nil {
		return errors.New("invalid geodata document")
	}
	for _, asset := range assets.Geodata.Assets {
		if asset.File != "geosite.dat" {
			return errors.New("agents accept only geosite.dat domain assets")
		}
	}
	policy := config.Firewall.SourceGeoIP
	if policy == nil {
		return nil
	}
	if !config.Firewall.Enabled {
		return errors.New("invalid source GeoIP policy or disabled firewall")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	for _, listener := range policy.Listeners {
		if err := validateSourceListener(config.Xray, listener); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks transport bounds independently of the current Xray document.
func (policy SourceGeoIPPolicy) Validate() error {
	if policy.Reference && len(policy.Prefixes) > 0 {
		return errors.New("source GeoIP references cannot carry prefixes")
	}
	if !ValidName(policy.Generation) || len(policy.Prefixes) > 500000 || len(policy.Listeners) > 256 {
		return errors.New("invalid source GeoIP policy")
	}
	for _, raw := range policy.Prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return errors.New("invalid source GeoIP prefix")
		}
	}
	for _, listener := range policy.Listeners {
		if listener.Port < 1 || listener.Port > 65535 || listener.Network != "tcp" && listener.Network != "udp" {
			return errors.New("invalid source GeoIP listener")
		}
		if listener.ListenIP != "" {
			if _, err := netip.ParseAddr(listener.ListenIP); err != nil {
				return errors.New("invalid source GeoIP listen address")
			}
		}
	}
	return nil
}

func containsGeoIP(value any, field string) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			if containsGeoIP(item, key) {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if containsGeoIP(item, field) {
				return true
			}
		}
	case string:
		if strings.HasPrefix(value, "geoip:") || strings.HasPrefix(value, "ext-ip:") || strings.HasPrefix(value, "ext:") && (field == "ip" || field == "sourceIP" || field == "expectedIPs" || field == "unexpectedIPs") {
			return true
		}
	}
	return false
}
