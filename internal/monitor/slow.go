package monitor

import (
	"context"
	gnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
	"time"
)

// Socket/process/GPU scans have their own bounded cadence, independent of reports.
func (s *Sampler) collectSlow(ctx context.Context, now time.Time, out *Snapshot) {
	if !s.slowAt.IsZero() && now.Sub(s.slowAt) < 10*time.Second {
		out.TCP, out.UDP, out.Processes, out.GPU = s.slow.TCP, s.slow.UDP, s.slow.Processes, s.slow.GPU
		for key, value := range s.slow.Errors {
			out.Errors[key] = value
		}
		return
	}
	connections, e := gnet.ConnectionsWithContext(ctx, "all")
	if e != nil {
		out.Errors["connections"] = "unavailable"
	} else {
		for _, c := range connections {
			if c.Type == 1 {
				out.TCP++
			} else if c.Type == 2 {
				out.UDP++
			}
		}
	}
	pids, e := process.PidsWithContext(ctx)
	if e != nil {
		out.Errors["processes"] = "unavailable"
	} else {
		out.Processes = len(pids)
	}
	out.GPU = collectGPU(ctx)

	s.slowAt = now
	s.slow = Snapshot{TCP: out.TCP, UDP: out.UDP, Processes: out.Processes, GPU: out.GPU, Errors: map[string]string{}}
	for _, key := range []string{"connections", "processes"} {
		if value := out.Errors[key]; value != "" {
			s.slow.Errors[key] = value
		}
	}
}
