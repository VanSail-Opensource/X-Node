package monitor

import (
	"bytes"
	"encoding/json"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

func TestMachineSnapshotIsolationAndWireShape(t *testing.T) {
	sample := Snapshot{
		Time:       time.Now().UTC(),
		Host:       &host.InfoStat{Hostname: "node"},
		Load:       &load.AvgStat{Load1: 1.1},
		Memory:     &mem.VirtualMemoryStat{Total: 2048},
		Swap:       &mem.SwapMemoryStat{Total: 1024},
		CPU:        []cpu.InfoStat{{Flags: []string{"sse4"}}},
		CPUUsage:   []float64{3.0},
		Disks:      []Disk{{Mount: "/"}},
		DiskIO:     map[string]disk.IOCountersStat{"sda": {Name: "sda"}},
		Interfaces: []Interface{{Name: "lo", Addresses: []string{"127.0.0.1/8"}}},
		GPU:        []GPU{{Name: "gpu"}},
		Errors:     map[string]string{"swap": "unavailable"},
	}
	s := New()
	s.latest.Store(&sample)
	want, err := json.Marshal(protocol.Clone(sample))
	if err != nil {
		t.Fatal(err)
	}

	copy := s.Snapshot()
	copy.Host.Hostname = "changed"
	copy.Load.Load1 = 2.1
	copy.Memory.Total = 4
	copy.Swap.Total = 5
	copy.CPU[0].Flags[0] = "changed"
	copy.CPUUsage[0] = 100
	copy.Disks[0].Mount = "/changed"
	delete(copy.DiskIO, "sda")
	copy.Interfaces[0].Name = "changed"
	copy.Interfaces[0].Addresses[0] = "changed"
	copy.GPU[0].Name = "changed"
	delete(copy.Errors, "swap")

	got, err := s.SnapshotJSON()
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("machine snapshot leaked mutation or changed wire shape: %s, error %v", got, err)
	}
	got[0] = 0
	again, err := s.SnapshotJSON()
	if err != nil || !bytes.Equal(again, want) {
		t.Fatalf("mutating machine report changed the next report: %s, error %v", again, err)
	}
}

func TestRuntimeSampleCompletedGC(t *testing.T) {
	var s runtimeSample
	var before, after Snapshot
	s.collect(&before)
	runtime.GC()
	s.collect(&after)
	var want runtime.MemStats
	runtime.ReadMemStats(&want)
	if after.GoHeap == 0 || after.GCCount <= before.GCCount || after.GCPauseNanos < before.GCPauseNanos {
		t.Fatalf("runtime samples did not advance across GC: %+v, %+v", before, after)
	}
	if after.GCCount == want.NumGC && after.GCPauseNanos != want.PauseTotalNs {
		t.Fatalf("pause total = %d, want %d", after.GCPauseNanos, want.PauseTotalNs)
	}
}

func BenchmarkMachineSnapshot(b *testing.B) {
	oneCPU := cpu.InfoStat{Flags: []string{"flag0", "flag1", "flag2", "flag3"}}
	s := New()
	s.latest.Store(&Snapshot{
		Time:       time.Now().UTC(),
		CPU:        slices.Repeat([]cpu.InfoStat{oneCPU}, 32),
		CPUUsage:   make([]float64, 32),
		Interfaces: []Interface{{Name: "eth0", Addresses: []string{"192.0.2.1/24"}}},
	})
	b.Run("legacy-report", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := json.Marshal(protocol.Clone(*s.latest.Load())); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("report", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.SnapshotJSON(); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRuntimeSample(b *testing.B) {
	b.Run("legacy-memstats", func(b *testing.B) {
		b.ReportAllocs()
		var m runtime.MemStats
		for b.Loop() {
			runtime.ReadMemStats(&m)
		}
	})
	b.Run("targeted", func(b *testing.B) {
		b.ReportAllocs()
		var s runtimeSample
		var out Snapshot
		s.collect(&out)
		for b.Loop() {
			s.collect(&out)
		}
	})
}
