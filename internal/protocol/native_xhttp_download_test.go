package protocol

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
)

func TestXHTTPRejectsDownloadShapesThatPassBuildButCannotBeDialed(t *testing.T) {
	for _, download := range []string{
		`{"port":443,"network":"xhttp"}`,
		`{"address":"127.0.0.1","network":"xhttp"}`,
		`{"address":"127.0.0.1","port":443}`,
		`{"address":"127.0.0.1","port":443,"network":"xhttp","method":"raw"}`,
		`{"address":"127.0.0.1","port":443,"network":"ws"}`,
	} {
		t.Run(download, func(t *testing.T) {
			stream := `{"network":"xhttp","xhttpSettings":{"downloadSettings":` + download + `}}`
			var native conf.StreamConfig
			if err := json.Unmarshal([]byte(stream), &native); err != nil {
				t.Fatal(err)
			}
			built, err := native.Build()
			if err != nil {
				t.Fatal("fixture must demonstrate a native build that succeeds", err)
			}
			actual := parityXHTTPTransport(t, built).DownloadSettings
			if actual.Address != nil && actual.Port != 0 && actual.ProtocolName == "splithttp" {
				t.Fatal("fixture does not reach an unsafe download shape")
			}
			if err = ValidateNativePolicies(Config{Xray: memberTransportDocument(t, stream)}); err == nil {
				t.Fatal("unsafe native download accepted before listener activation")
			}
		})
	}
}

func TestXHTTPDownloadValidationKeepsOperatorEndpointsAndNativeAliasPrecedence(t *testing.T) {
	for _, stream := range []string{
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"127.0.0.1","port":443,"network":"xhttp"}}}`,
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{"address":"download.example","port":443,"network":"raw","method":"SPLITHTTP"}}}`,
		`{"network":"xhttp","xhttpSettings":{"downloadSettings":{},"extra":{}}}`,
		`{"network":"xhttp","splithttpSettings":{"downloadSettings":{}},"xhttpSettings":{}}`,
	} {
		if err := ValidateNativePolicies(Config{Xray: memberTransportDocument(t, stream)}); err != nil {
			t.Fatal("safe native download configuration rejected", stream, err)
		}
	}
}
