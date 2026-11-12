package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func dependencyPeer(t *testing.T, stream string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(`{"tag":"peer","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"`+testUUID+`","encryption":"none"}]}]},"streamSettings":`+stream+`}`), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func dependencyConfig(t *testing.T, peer map[string]any, hop string) protocol.Config {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"inbounds": []any{},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			peer,
			map[string]any{"tag": "hop", "protocol": hop},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Config{Xray: raw}
}

func TestOutboundValidationIncludesEffectiveXHTTPDialers(t *testing.T) {
	for _, test := range []struct {
		name, stream string
		invalid      bool
	}{
		{"missing download peer", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"missing"}}}}`, true},
		{"download self cycle", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"peer"}}}}`, true},
		{"extra alias cycle", `{"network":"splithttp","splithttpSettings":{"extra":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"peer"}}}}}`, true},
		{"native case cycle", `{"Network":"xhttp","XHTTPSettings":{"DownloadSettings":{"Address":"127.0.0.1","Port":443,"Network":"xhttp","Sockopt":{"DialerProxy":"peer"}}}}`, true},
		{"native case main cycle", `{"Network":"tcp","Sockopt":{"DialerProxy":"peer"}}`, true},
		{"valid download peer", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"hop"}}}}`, false},
		{"extra replaces ignored dependency", `{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"missing"}},"extra":{}}}`, false},
		{"preferred alias replaces ignored dependency", `{"network":"xhttp","splithttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"missing"}}},"xhttpSettings":{}}`, false},
		{"penetrating socket replaces download socket", `{"network":"xhttp","sockopt":{"dialerProxy":"hop","penetrate":true},"xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"missing"}}}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := Prepare(dependencyConfig(t, dependencyPeer(t, test.stream), "freedom"))
			if test.invalid {
				if err == nil || !strings.Contains(err.Error(), "dependency") {
					t.Fatalf("unsafe dependency was not rejected at preparation: %v", err)
				}
			} else if err != nil {
				t.Fatal("valid effective dependency was rejected", err)
			}
		})
	}
}

func TestNestedXHTTPDependencyDisablesIndependentReplacement(t *testing.T) {
	peer := dependencyPeer(t, `{"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp","sockopt":{"dialerProxy":"hop"}}}}}`)
	old, err := Prepare(dependencyConfig(t, peer, "freedom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"dependency", "dependent"} {
		t.Run(changed, func(t *testing.T) {
			candidate := protocol.Clone(peer)
			hop := "freedom"
			if changed == "dependency" {
				hop = "blackhole"
			} else {
				candidate["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = "127.0.0.2"
			}
			next, err := PrepareCached(dependencyConfig(t, candidate, hop), old)
			if err != nil {
				t.Fatal(err)
			}
			if hotEligible(old, next) {
				t.Fatal("chained XHTTP outbound was classified as an independent replacement")
			}
		})
	}
}

func TestClientPreparationRejectsUnsafeXHTTP(t *testing.T) {
	for _, stream := range []string{
		`{"network":"xhttp","xhttpSettings":{"h2Params":{"MaxConcurrentStreams":"invalid"}}}`,
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{"port":443,"network":"xhttp"}}}`,
		`{"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"tcp"}}}}`,
	} {
		t.Run(stream, func(t *testing.T) {
			if _, err := prepareClient(map[string]any{"outbounds": []any{dependencyPeer(t, stream)}}); err == nil {
				t.Fatal("probe/download client accepted unsafe XHTTP settings")
			}
		})
	}
}

func TestNativeCaseMuxDisablesIndependentReplacement(t *testing.T) {
	peer := dependencyPeer(t, `{"network":"tcp"}`)
	peer["Mux"] = map[string]any{"enabled": true, "concurrency": 8}
	old, err := Prepare(dependencyConfig(t, peer, "freedom"))
	if err != nil {
		t.Fatal(err)
	}
	peer["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = "127.0.0.2"
	next, err := PrepareCached(dependencyConfig(t, peer, "freedom"), old)
	if err != nil {
		t.Fatal(err)
	}
	if hotEligible(old, next) {
		t.Fatal("native case alias bypassed mux reconstruction")
	}
}
