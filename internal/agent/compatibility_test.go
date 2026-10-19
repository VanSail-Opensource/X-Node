package agent

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestNewCapabilityCannotHideBehindExistingAccountingExtension(t *testing.T) {
	before := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`), Users: []protocol.User{{ID: 1, AccountingPeriod: "period"}}}
	next := protocol.Clone(before)
	next.Xray = json.RawMessage(`{"inbounds":[{"tag":"utility","protocol":"tunnel"}]}`)
	if !adoptsManagedExtensions(next, before) {
		t.Fatal("new utility capability was adopted during an unconfirmed upgrade")
	}
	if adoptsManagedExtensions(next, next) {
		t.Fatal("unchanged cached capability requires a new adoption")
	}
	next = protocol.Clone(before)
	next.MemberOutbounds = []string{"member"}
	if !adoptsManagedExtensions(next, before) {
		t.Fatal("new member guard hidden by existing period accounting")
	}
}

func TestPendingUpgradeCannotAdoptNewAssetOrCertificateContracts(t *testing.T) {
	before := protocol.Config{Xray: json.RawMessage(`{"inbounds":[]}`), Firewall: protocol.FirewallPolicy{SourceGeoIP: &protocol.SourceGeoIPPolicy{Generation: "inline"}}}
	for _, test := range []struct {
		name   string
		mutate func(*protocol.Config)
	}{
		{"country stream", func(c *protocol.Config) { c.Firewall.SourceGeoIP.Reference = true }},
		{"node files", func(c *protocol.Config) {
			c.Certificates = map[string]protocol.Certificate{"tls": {Config: config.CertConfig{CertMode: "file", CertFile: "/private/cert.pem", KeyFile: "/private/key.pem"}}}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := protocol.Clone(before)
			test.mutate(&next)
			if !adoptsManagedExtensions(next, before) || adoptsManagedExtensions(next, next) {
				t.Fatal("pending upgrade lost its first-adoption fence")
			}
		})
	}
}
