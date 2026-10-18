package protocol

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/config"
)

func TestNodeFilesDoNotRequireAcmeIdentity(t *testing.T) {
	c := Config{Xray: json.RawMessage(`{"inbounds":[]}`), Certificates: map[string]Certificate{"files": {Config: config.CertConfig{CertMode: "file", CertFile: "/etc/x-node/cert.pem", KeyFile: "/etc/x-node/key.pem"}}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	profile := c.Certificates["files"]
	profile.Config.KeyFile = ""
	c.Certificates["files"] = profile
	if err := c.Validate(); err == nil {
		t.Fatal("missing node key accepted")
	}
	profile.Config.CertMode = "http"
	c.Certificates["files"] = profile
	if err := c.Validate(); err == nil {
		t.Fatal("ACME without domain accepted")
	}
}
