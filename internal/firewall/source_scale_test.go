package firewall

import (
	"bufio"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Hosted regression for the source-processing budget. Kernel set memory and
// unrelated Xray/session workloads are outside this userspace inventory budget.
func TestTenMillionSourceRecordsBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("large hosted inventory regression")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bulk"), 0700); err != nil {
		t.Fatal(err)
	}
	input, output := filepath.Join(dir, "bulk", "input"), filepath.Join(dir, "bulk", "output")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 64<<10)
	var peak atomic.Uint64
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	defer func() { close(done); <-stopped }()
	for i := maxSourcePrefixes - 1; i >= 0; i-- {
		// Alternating host IPs and /31 CIDRs separated by gaps do not merge.
		var r diskRange
		r[0] = 4
		r[11], r[12] = 255, 255
		binary.BigEndian.PutUint32(r[13:17], uint32(0x08000000+i*4))
		copy(r[17:], r[1:17])
		r[32] += byte(i % 2)
		if _, err = w.Write(r[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = sortSourceRecords(context.Background(), dir, input, output); err != nil {
		t.Fatal(err)
	}
	budget, sparse := int64(sourceLookupBytes), int64(4<<20)
	var lookup sourceLookup
	if err = lookup.open(output, &budget, &sparse); err != nil {
		t.Fatal(err)
	}
	if lookup.file == nil || lookup.count != maxSourcePrefixes {
		t.Fatal("large inventory became resident or lost ranges")
	}
	defer lookup.file.Close()
	if err = os.Remove(output); err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	for _, i := range []int{0, 255, 256, 1_000_001, maxSourcePrefixes - 1} {
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], uint32(0x08000000+i*4))
		if found, err := lookup.contains(netip.AddrFrom4(ip)); err != nil || !found {
			t.Fatal(i, found, err)
		}
	}
	if peak.Load() > 256<<20 {
		t.Fatalf("inventory peak heap %d exceeds 256 MiB", peak.Load())
	}
	t.Logf("10,000,000 IP/CIDR records; peak heap %d; resident lookup index %d bytes", peak.Load(), len(lookup.blocks)*rangeBytes)
}
