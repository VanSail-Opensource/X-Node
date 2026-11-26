package monitor

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/shirou/gopsutil/v4/common"
)

func socketCounts(ctx context.Context) (tcp, udp int, err error) {
	env, _ := ctx.Value(common.EnvKey).(common.EnvMap)
	root := env[common.HostProcEnvKey]
	if root == "" {
		root = os.Getenv(string(common.HostProcEnvKey))
	}
	if root == "" {
		root = "/proc"
	}

	// Telemetry needs table row counts, not addresses, owners or FD-to-
	// inode mapping. Do not walk every process or include Unix sockets.
	var scratch [8 << 10]byte
	for _, table := range [...]string{"tcp", "tcp6", "udp", "udp6"} {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		file, err := os.Open(filepath.Join(root, "net", table))
		if err != nil {
			if table[len(table)-1] == '6' && os.IsNotExist(err) {
				continue // IPv6 can be disabled in the kernel.
			}
			return 0, 0, err
		}
		count, err := countSocketRows(ctx, file, scratch[:])
		_ = file.Close()
		if err != nil {
			return 0, 0, fmt.Errorf("%s sockets: %w", table, err)
		}
		if table[0] == 't' {
			tcp += count
		} else {
			udp += count
		}
	}
	return tcp, udp, nil
}

func countSocketRows(ctx context.Context, reader io.Reader, scratch []byte) (int, error) {
	scan := bufio.NewScanner(reader)
	scan.Buffer(scratch, bufio.MaxScanTokenSize)
	if !scan.Scan() { // skip the kernel column header
		if err := scan.Err(); err != nil {
			return 0, err
		}
		return 0, io.ErrUnexpectedEOF
	}
	count := 0
	for scan.Scan() {
		if count%256 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		if len(bytes.Trim(scan.Bytes(), " \t\r")) > 0 {
			count++
		}
	}
	if err := scan.Err(); err != nil {
		return 0, err
	}
	return count, ctx.Err()
}
