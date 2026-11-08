package xrayconfig_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/pkg/protocol"
	"github.com/VanSail-Opensource/X-Node/pkg/xrayconfig"
)

func TestPublicValidatorsRejectMalformedXHTTPWithoutReplacingCachedCandidate(t *testing.T) {
	config := protocol.Config{Xray: json.RawMessage(`{"inbounds":[{"tag":"in","listen":"127.0.0.1","port":12345,"protocol":"vless","settings":{"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"path":"/stream","h2Params":{"MaxConcurrentStreams":32}}}}]}`)}
	var cached xrayconfig.Validator
	if err := xrayconfig.Validate(config); err != nil {
		t.Fatal(err)
	}
	if _, err := xrayconfig.Render(config); err != nil {
		t.Fatal(err)
	}
	if err := cached.Validate(config); err != nil {
		t.Fatal(err)
	}
	before := cached.Counts()
	invalid := config
	invalid.Xray = json.RawMessage(strings.Replace(string(config.Xray), `"MaxConcurrentStreams":32`, `"MaxConcurrentStreams":"invalid"`, 1))
	if err := xrayconfig.Validate(invalid); err == nil {
		t.Fatal("public validation accepted deferred HTTP/2 type error")
	}
	if _, err := xrayconfig.Render(invalid); err == nil {
		t.Fatal("public rendering accepted deferred HTTP/2 type error")
	}
	if err := cached.Validate(invalid); err == nil || cached.Counts() != before {
		t.Fatal("invalid candidate reached native construction or changed the cache", err)
	}
	if err := cached.Validate(config); err != nil || cached.Counts() != before {
		t.Fatal("invalid candidate replaced the working cached configuration", err)
	}
}
