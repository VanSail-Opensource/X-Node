// Package monitor samples host metrics once and publishes immutable snapshots.
package monitor

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

type Disk struct {
	Mount      string `json:"mount"`
	Filesystem string `json:"filesystem"`
	Total      uint64 `json:"total"`
	Used       uint64 `json:"used"`
	Free       uint64 `json:"free"`
}
type Interface struct {
	Name        string   `json:"name"`
	Addresses   []string `json:"addresses"`
	Sent        uint64   `json:"sent"`
	Received    uint64   `json:"received"`
	UploadBPS   float64  `json:"upload_bps"`
	DownloadBPS float64  `json:"download_bps"`
}
type GPU struct {
	Name        string  `json:"name"`
	MemoryTotal uint64  `json:"memory_total"`
	MemoryUsed  uint64  `json:"memory_used"`
	Utilization float64 `json:"utilization"`
	Temperature float64 `json:"temperature"`
}
type Snapshot struct {
	Time           time.Time                      `json:"time"`
	ElapsedSeconds float64                        `json:"elapsed_seconds"`
	Host           *host.InfoStat                 `json:"host,omitempty"`
	CPU            []cpu.InfoStat                 `json:"cpu_info,omitempty"`
	CPUUsage       []float64                      `json:"cpu_usage"`
	Load           *load.AvgStat                  `json:"load,omitempty"`
	Memory         *mem.VirtualMemoryStat         `json:"memory,omitempty"`
	Swap           *mem.SwapMemoryStat            `json:"swap,omitempty"`
	Disks          []Disk                         `json:"disks"`
	DiskIO         map[string]disk.IOCountersStat `json:"disk_io,omitempty"`
	Interfaces     []Interface                    `json:"interfaces"`
	TCP            int                            `json:"tcp"`
	UDP            int                            `json:"udp"`
	Processes      int                            `json:"processes"`
	GPU            []GPU                          `json:"gpu,omitempty"`
	Goroutines     int                            `json:"goroutines"`
	GoHeap         uint64                         `json:"go_heap"`
	GCCount        uint32                         `json:"gc_count"`
	GCPauseNanos   uint64                         `json:"gc_pause_nanos"`
	Errors         map[string]string              `json:"errors,omitempty"`
}
type Sampler struct {
	latest   atomic.Pointer[Snapshot]
	interval atomic.Int64
	previous map[string]gnet.IOCountersStat
	last     time.Time
	slowAt   time.Time
	slow     Snapshot
	hostInfo *host.InfoStat
	cpuInfo  []cpu.InfoStat
}

func New() *Sampler {
	s := &Sampler{previous: map[string]gnet.IOCountersStat{}}
	s.interval.Store(int64(time.Second))
	return s
}
func (s *Sampler) Interval(d time.Duration) {
	if d < time.Second {
		d = time.Second
	}
	s.interval.Store(int64(d))
}
func (s *Sampler) Snapshot() Snapshot {
	if p := s.latest.Load(); p != nil {
		return protocol.Clone(*p)
	}
	return Snapshot{}
}
func (s *Sampler) Run(ctx context.Context) {
	for {
		snapshot := s.collect(ctx, time.Now())
		s.latest.Store(&snapshot)
		timer := time.NewTimer(time.Duration(s.interval.Load()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (s *Sampler) collect(ctx context.Context, now time.Time) Snapshot {
	out := Snapshot{Time: now.UTC(), Disks: []Disk{}, Interfaces: []Interface{}, Errors: map[string]string{}}
	if !s.last.IsZero() {
		out.ElapsedSeconds = now.Sub(s.last).Seconds()
	}
	if s.hostInfo == nil {
		s.hostInfo, _ = host.InfoWithContext(ctx)
	}
	if s.cpuInfo == nil {
		s.cpuInfo, _ = cpu.InfoWithContext(ctx)
	}
	out.Host = s.hostInfo
	out.CPU = s.cpuInfo
	var e error
	out.CPUUsage, e = cpu.PercentWithContext(ctx, 0, true)
	if e != nil {
		out.Errors["cpu"] = "unavailable"
	}
	out.Load, e = load.AvgWithContext(ctx)
	if e != nil {
		out.Errors["load"] = "unavailable"
	}
	out.Memory, e = mem.VirtualMemoryWithContext(ctx)
	if e != nil {
		out.Errors["memory"] = "unavailable"
	}
	out.Swap, e = mem.SwapMemoryWithContext(ctx)
	if e != nil {
		out.Errors["swap"] = "unavailable"
	}
	partitions, e := disk.PartitionsWithContext(ctx, false)
	if e != nil {
		out.Errors["disks"] = "unavailable"
	}
	for _, p := range partitions {
		usage, e := disk.UsageWithContext(ctx, p.Mountpoint)
		if e == nil {
			out.Disks = append(out.Disks, Disk{Mount: p.Mountpoint, Filesystem: p.Fstype, Total: usage.Total, Used: usage.Used, Free: usage.Free})
		}
	}
	out.DiskIO, e = disk.IOCountersWithContext(ctx)
	if e != nil {
		out.Errors["disk_io"] = "unavailable"
	}
	nics, _ := net.Interfaces()
	addresses := map[string][]string{}
	for _, nic := range nics {
		values, _ := nic.Addrs()
		for _, v := range values {
			addresses[nic.Name] = append(addresses[nic.Name], v.String())
		}
	}
	counters, e := gnet.IOCountersWithContext(ctx, true)
	if e != nil {
		out.Errors["network"] = "unavailable"
	}
	next := map[string]gnet.IOCountersStat{}
	for _, n := range counters {
		entry := Interface{Name: n.Name, Addresses: addresses[n.Name], Sent: n.BytesSent, Received: n.BytesRecv}
		if old, ok := s.previous[n.Name]; ok && out.ElapsedSeconds > 0 {
			if n.BytesSent >= old.BytesSent {
				entry.UploadBPS = float64(n.BytesSent-old.BytesSent) / out.ElapsedSeconds
			}
			if n.BytesRecv >= old.BytesRecv {
				entry.DownloadBPS = float64(n.BytesRecv-old.BytesRecv) / out.ElapsedSeconds
			}
		}
		out.Interfaces = append(out.Interfaces, entry)
		next[n.Name] = n
	}
	s.previous = next
	s.last = now
	s.collectSlow(ctx, now, &out)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	out.Goroutines = runtime.NumGoroutine()
	out.GoHeap = m.HeapAlloc
	out.GCCount = m.NumGC
	out.GCPauseNanos = m.PauseTotalNs
	return out
}
