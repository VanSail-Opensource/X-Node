package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

func benchmarkConfig(b *testing.B, users int) protocol.Config {
	b.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	c := protocol.Config{Xray: json.RawMessage(fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"tag":"paid","listen":"127.0.0.1","port":%d,"protocol":"vless","settings":{"decryption":"none"}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`, port)), Users: []protocol.User{}}
	for id := 1; id <= users; id++ {
		c.Users = append(c.Users, protocol.User{ID: id, UUID: fmt.Sprintf("550e8400-e29b-41d4-a716-%012x", id), InboundTags: []string{"paid"}})
	}
	return c
}

func BenchmarkConfigPreparation(b *testing.B) {
	for _, users := range []int{1, 1000} {
		for _, reuse := range []bool{false, true} {
			b.Run(fmt.Sprintf("users=%d/cached=%t", users, reuse), func(b *testing.B) {
				c := benchmarkConfig(b, users)
				previous, err := Prepare(c)
				if err != nil {
					b.Fatal(err)
				}
				if !reuse {
					previous = nil
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := PrepareCached(c, previous); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkRoutingApply(b *testing.B) {
	for _, force := range []bool{false, true} {
		b.Run(fmt.Sprintf("rebuild=%t", force), func(b *testing.B) {
			c := benchmarkConfig(b, 1)
			registry := sessions.New()
			registry.SetUsers(c.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err := runtime.Apply(context.Background(), c); err != nil {
				b.Fatal(err)
			}
			var root map[string]any
			_ = json.Unmarshal(c.Xray, &root)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				root["routing"] = map[string]any{"rules": []any{map[string]any{"type": "field", "domain": []string{fmt.Sprintf("full:route-%d.invalid", i%2)}, "outboundTag": "direct"}}}
				c.Xray, _ = json.Marshal(root)
				if err := runtime.Apply(context.Background(), c, force); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			stats := runtime.Statistics()
			b.ReportMetric(float64(stats.Rebuilds-1), "rebuilds")
			b.ReportMetric(float64(stats.ListenerGapMillis), "last-gap-ms")
			b.ReportMetric(float64(stats.ListenerGapMicros), "last-gap-us")
		})
	}
}

// force=true reproduces the previous runtime.reload behavior as its baseline.
func BenchmarkRuntimeReload(b *testing.B) {
	for _, force := range []bool{false, true} {
		b.Run(fmt.Sprintf("force=%t", force), func(b *testing.B) {
			c := benchmarkConfig(b, 1)
			registry := sessions.New()
			registry.SetUsers(c.Users)
			runtime := New(registry)
			defer runtime.Stop()
			if err := runtime.Apply(context.Background(), c); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := runtime.Apply(context.Background(), c, force); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			stats := runtime.Statistics()
			b.ReportMetric(float64(stats.Rebuilds-1), "rebuilds")
			b.ReportMetric(float64(stats.ListenerGapMicros), "last-gap-us")
		})
	}
}
