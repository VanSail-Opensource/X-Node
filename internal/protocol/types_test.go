package protocol

import (
	"testing"
)

func TestExplicitEmptyUsers(t *testing.T) {
	for _, raw := range []string{`{"xray":{"inbounds":[]}}`, `{"xray":{"inbounds":[]},"users":null}`, `{"xray":{"inbounds":[]},"users":{}}`} {
		if _, e := ParseConfig([]byte(raw)); e == nil {
			t.Fatal("accepted absent/null users")
		}
	}
	c, e := ParseConfig([]byte(`{"xray":{"inbounds":[]},"users":[]}`))
	if e != nil || c.Users == nil {
		t.Fatal("empty authoritative snapshot rejected")
	}
}
func TestStrictEnvelopeAndNestedClone(t *testing.T) {
	if _, e := Parse([]byte(`{"v":1,"type":"hello","token":"leak"}`)); e == nil {
		t.Fatal("unknown envelope accepted")
	}
	if _, e := Parse([]byte(`{"v":2,"type":"hello"}`)); e == nil {
		t.Fatal("future version accepted")
	}
	a := map[string]any{"nested": map[string]any{"list": []any{"old"}}}
	b := Clone(a)
	b["nested"].(map[string]any)["list"].([]any)[0] = "new"
	if a["nested"].(map[string]any)["list"].([]any)[0] != "old" {
		t.Fatal("nested alias")
	}
}
