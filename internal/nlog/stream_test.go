package nlog

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestRedactionBoundsAndConcurrentReaders(t *testing.T) {
	var out bytes.Buffer
	s := NewStream(&out)
	s.Secrets("token-secret", "token-secret-long")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 200 {
				_, _ = s.Write([]byte("token-secret-long token-secret"))
			}
		})
	}
	workers.Wait()
	entries, dropped := s.Drain()
	if len(entries) != 1024 || dropped != 576 {
		t.Fatalf("bounded queue: %d entries %d drops", len(entries), dropped)
	}
	if strings.Contains(out.String(), "token-secret") {
		t.Fatal("console leaked secret")
	}
	for _, e := range entries {
		if strings.Contains(e.Text, "token-secret") {
			t.Fatal("remote log leaked secret")
		}
	}
	s.Write([]byte(strings.Repeat("x", 9000)))
	truncated, _ := s.Drain()
	if len(truncated[0].Text) > 8210 {
		t.Fatal("unbounded log entry")
	}
	entries[0].Text = "mutated"
	next, _ := s.Drain()
	if len(next) != 0 {
		t.Fatal("drain aliased live state")
	}
}
