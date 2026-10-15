package agent

import (
	"encoding/json"
	"testing"

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
