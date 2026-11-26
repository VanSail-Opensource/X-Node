//go:build linux

package monitor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shirou/gopsutil/v4/common"
)

// Only protocol totals are reported. Linux exposes these tables for the sampler's
// network namespace directly, without mapping every process FD to a socket.
func socketCounts(ctx context.Context) (tcp, udp int, err error) {
	procRoot := ""
	if env, ok := ctx.Value(common.EnvKey).(common.EnvMap); ok {
		procRoot = env[common.HostProcEnvKey]
	}
	if procRoot == "" {
		procRoot = os.Getenv("HOST_PROC")
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	tcp, err = countProtocolSockets(ctx, procRoot, "tcp")
	if err != nil {
		return 0, 0, err
	}
	udp, err = countProtocolSockets(ctx, procRoot, "udp")
	if err != nil {
		return 0, 0, err
	}
	return tcp, udp, nil
}

func countProtocolSockets(ctx context.Context, procRoot, protocol string) (int, error) {
	count, err := countProcSocketFile(ctx, filepath.Join(procRoot, "net", protocol))
	if err != nil {
		return 0, fmt.Errorf("%s socket table: %w", protocol, err)
	}
	v6, err := countProcSocketFile(ctx, filepath.Join(procRoot, "net", protocol+"6"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%s6 socket table: %w", protocol, err)
	}
	return count + v6, nil
}

func countProcSocketFile(ctx context.Context, path string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	lines := bufio.NewScanner(f)
	if !lines.Scan() {
		if err := lines.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("missing socket table header")
	}
	n := 0
	for lines.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		for _, b := range lines.Bytes() {
			if b != ' ' && b != '\t' && b != '\r' {
				n++
				break
			}
		}
	}
	return n, lines.Err()
}
