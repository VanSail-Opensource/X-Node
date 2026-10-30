package monitor

import (
	"context"
	"encoding/csv"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func collectGPU(ctx context.Context) []GPU {
	var out []GPU
	if _, e := exec.LookPath("nvidia-smi"); e == nil {
		child, cancel := context.WithTimeout(ctx, time.Second)
		b, e := exec.CommandContext(child, "nvidia-smi", "--query-gpu=name,memory.total,memory.used,utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits").Output()
		cancel()
		if e == nil {
			rows, _ := csv.NewReader(strings.NewReader(string(b))).ReadAll()
			for _, row := range rows {
				if len(row) != 5 {
					continue
				}
				total, _ := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
				used, _ := strconv.ParseFloat(strings.TrimSpace(row[2]), 64)
				util, _ := strconv.ParseFloat(strings.TrimSpace(row[3]), 64)
				temp, _ := strconv.ParseFloat(strings.TrimSpace(row[4]), 64)
				out = append(out, GPU{Name: strings.TrimSpace(row[0]), MemoryTotal: uint64(total * 1048576), MemoryUsed: uint64(used * 1048576), Utilization: util, Temperature: temp})
			}
		}
	}
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*/device")
	for _, dir := range cards {
		vendor, _ := os.ReadFile(filepath.Join(dir, "vendor"))
		if strings.TrimSpace(string(vendor)) != "0x1002" {
			continue
		}
		read := func(name string) uint64 {
			b, _ := os.ReadFile(filepath.Join(dir, name))
			n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
			return n
		}
		name, _ := os.ReadFile(filepath.Join(dir, "product_name"))
		if len(name) == 0 {
			name = []byte("AMD GPU")
		}
		gpu := GPU{Name: strings.TrimSpace(string(name)), MemoryTotal: read("mem_info_vram_total"), MemoryUsed: read("mem_info_vram_used"), Utilization: float64(read("gpu_busy_percent"))}
		temps, _ := filepath.Glob(filepath.Join(dir, "hwmon", "hwmon*", "temp1_input"))
		if len(temps) > 0 {
			b, _ := os.ReadFile(temps[0])
			n, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			gpu.Temperature = n / 1000
		}
		out = append(out, gpu)
	}
	return out
}
