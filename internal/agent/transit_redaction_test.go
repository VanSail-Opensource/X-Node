package agent

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
	xlog "github.com/xtls/xray-core/common/log"
)

func TestTransitCredentialsAreRedactedFromLocalAndRemoteLogs(t *testing.T) {
	var console bytes.Buffer
	logs := nlog.NewStream(&console)
	a := &Agent{Logs: logs, Client: &transport.Client{Token: "control-token"}}
	a.registerSecrets(protocol.Config{Users: []protocol.User{{
		UUID:        "member-uuid",
		Credentials: map[string]json.RawMessage{"in": json.RawMessage(`{"password":"member-password"}`)},
		TransitCredentials: []protocol.TransitCredential{
			{Credential: json.RawMessage(`{"id":"peer-uuid"}`)},
			{Credential: json.RawMessage(`{"password":"peer-password"}`)},
		},
	}}})
	message := "control-token member-uuid member-password peer-uuid peer-password"
	if _, err := logs.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	logs.Handle(&xlog.GeneralMessage{Severity: xlog.Severity_Warning, Content: message})
	entries, _ := logs.Drain()
	if len(entries) != 2 {
		t.Fatal("missing agent/native log entries", entries)
	}
	for _, secret := range strings.Fields(message) {
		if strings.Contains(console.String(), secret) || strings.Contains(logs.Redact(message), secret) {
			t.Fatal("local logging or command-error redaction exposed a credential")
		}
		for _, entry := range entries {
			if strings.Contains(entry.Text, secret) {
				t.Fatal("remote log stream exposed a credential")
			}
		}
	}
}
