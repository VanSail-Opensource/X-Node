package agent

import (
	"slices"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestBinaryHourlyFormatSupportDoesNotEnableUnavailableRuntime(t *testing.T) {
	capabilities := BinaryCapabilities()
	if !slices.Contains(capabilities, protocol.HourlyCapability) {
		t.Fatal("version metadata omitted the hourly recovery format")
	}
	if slices.Contains((&Agent{}).runtimeCapabilities(), protocol.HourlyCapability) {
		t.Fatal("static format support advertised unavailable live admission")
	}
	capabilities[0] = "modified"
	if BinaryCapabilities()[0] == "modified" || Capabilities[0] == "modified" {
		t.Fatal("metadata caller changed the shared runtime capabilities")
	}
}
