package xray

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestRejectedEnvironmentCannotChangeProcessBeforeNativeValidation(t *testing.T) {
	t.Setenv("XRAY_BUF_READV", "original")
	before, present := os.LookupEnv("LD_PRELOAD")
	c := protocol.Config{Xray: json.RawMessage(`{"env":{"XRAY_BUF_READV":"true","LD_PRELOAD":"/untrusted"},"inbounds":[]}`)}
	if _, err := Prepare(c); err == nil {
		t.Fatal("native validator accepted unsafe environment")
	}
	if os.Getenv("XRAY_BUF_READV") != "original" {
		t.Fatal("partial environment was applied before rejection")
	}
	if after, exists := os.LookupEnv("LD_PRELOAD"); after != before || exists != present {
		t.Fatal("loader environment changed")
	}
}
