package xray

import (
	"encoding/json"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func editNative(t *testing.T, c protocol.Config, edit func(map[string]any)) protocol.Config {
	t.Helper()
	c = protocol.Clone(c)
	var root map[string]any
	if err := json.Unmarshal(c.Xray, &root); err != nil {
		t.Fatal(err)
	}
	edit(root)
	var err error
	c.Xray, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNativeBuildersReuseUnchangedSections(t *testing.T) {
	base, _ := testConfig(t)
	previous, err := Prepare(base)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		config protocol.Config
		want   BuildCounts
	}{
		{"unchanged", base, BuildCounts{}},
		{"rule", editNative(t, base, func(r map[string]any) {
			r["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "domain": []string{"full:example.com"}, "outboundTag": "direct"}}}
		}), BuildCounts{Routing: 1}},
		{"outbound", editNative(t, base, func(r map[string]any) {
			r["outbounds"] = append(r["outbounds"].([]any), map[string]any{"tag": "blocked", "protocol": "blackhole"})
		}), BuildCounts{Outbounds: 1}},
		{"dns", editNative(t, base, func(r map[string]any) { r["dns"] = map[string]any{"servers": []string{"localhost"}} }), BuildCounts{Native: 1}},
	}
	credential := protocol.Clone(base)
	credential.Users[0].UUID = "550e8400-e29b-41d4-a716-446655440001"
	cases = append(cases, struct {
		name   string
		config protocol.Config
		want   BuildCounts
	}{"credential", credential, BuildCounts{Inbounds: 1}})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next, err := PrepareCached(tc.config, previous)
			if err != nil {
				t.Fatal(err)
			}
			if next.Counts != tc.want {
				t.Fatalf("builders %+v, expected %+v", next.Counts, tc.want)
			}
			if tc.name != "credential" && next.Epochs["in"] != previous.Epochs["in"] {
				t.Fatal("global edit invalidated listener epoch")
			}
		})
	}
}
