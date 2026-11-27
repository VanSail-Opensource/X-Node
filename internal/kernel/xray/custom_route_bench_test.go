package xray

import (
	"encoding/json"
	"fmt"
	"testing"
)

func BenchmarkCustomRouteCompile(b *testing.B) {
	base := benchmarkConfig(b, 1)
	root := map[string]any{}
	if err := json.Unmarshal(base.Xray, &root); err != nil {
		b.Fatal(err)
	}
	rules := make([]any, 1000)
	for i := range rules {
		rules[i] = map[string]any{"type": "field", "ruleTag": fmt.Sprint(i), "domain": []string{fmt.Sprintf("full:member-%d.invalid", i)}, "outboundTag": "direct"}
	}
	root["routing"] = map[string]any{"rules": rules}
	base.Xray, _ = json.Marshal(root)
	old, err := Prepare(base)
	if err != nil {
		b.Fatal(err)
	}
	rules[500] = map[string]any{"type": "field", "ruleTag": "500", "domain": []string{"full:changed.invalid"}, "outboundTag": "direct"}
	base.Xray, _ = json.Marshal(root)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := PrepareCached(base, old); err != nil {
			b.Fatal(err)
		}
	}
}
