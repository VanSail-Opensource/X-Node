package state

import (
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"path/filepath"
	"testing"
)

func TestAcknowledgementNoOpAndPersistenceFailure(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddTraffic(Traffic{7: {10, 20}}); err != nil {
		t.Fatal(err)
	}
	first, err := s.Batch()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.AddTraffic(Traffic{7: {3, 4}}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Flush(); err != nil {
		t.Fatal(err)
	}
	if advanced, err := s.Acknowledge(first.ID); err != nil || !advanced {
		t.Fatal(advanced, err)
	}
	next := s.Pending()
	s.path = filepath.Join(s.path, "unwritable", "state.json")
	if advanced, err := s.Acknowledge(first.ID); err != nil || advanced {
		t.Fatalf("duplicate wrote disk: %t %v", advanced, err)
	}
	if advanced, err := s.Acknowledge(next.ID); err == nil || advanced {
		t.Fatalf("failed write advanced cursor: %t %v", advanced, err)
	}
	if got := s.Pending(); got.ID != next.ID || got.Traffic[7] != [2]uint64{3, 4} {
		t.Fatalf("journal changed: %+v", got)
	}
}

func BenchmarkReportingMetadata(b *testing.B) {
	s, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	s.data.Config = &protocol.Config{Users: []protocol.User{}}
	for i := 1; i <= 1000; i++ {
		s.data.Users = append(s.data.Users, protocol.User{ID: i, UUID: "synthetic-benchmark-credential", AccountingPeriod: "benchmark"})
	}
	b.Run("FullSnapshot", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = s.Snapshot().Revision
		}
	})
	b.Run("Metadata", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = s.Metadata()
		}
	})
}
