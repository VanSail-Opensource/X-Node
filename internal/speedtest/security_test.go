package speedtest

import (
	"context"
	"strings"
	"testing"
)

func TestSpeedtestRejectsUntrustedInitialURLsBeforeCreatingProxy(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1/private", "https://secret@probe.example/", "https://probe.example:invalid/", "https://probe.example/#fragment"} {
		_, err := Run(context.Background(), Request{DownloadURL: target, UploadURL: "https://upload.example/"}, func(string) { t.Error("invalid endpoint started probing") })
		if err == nil || !strings.Contains(err.Error(), "HTTPS") {
			t.Fatal("endpoint validation did not precede proxy creation", err)
		}
	}
}
