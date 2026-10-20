package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"go4.org/netipx"
)

// Ten million fixed-width records need 330 MB. Reserve staging, sorted
// output and a retained rollback generation without loading them into memory.
const bulkDiskLimit = 2 << 30
const maxSourcePrefixes = 10_000_000
const rangeBytes = 33

type diskRange [rangeBytes]byte

func prefixRecord(raw string) (diskRange, error) {
	var result diskRange
	p, err := protocol.FirewallPrefix(raw)
	if err != nil {
		return result, err
	}
	r := netipx.RangeOfPrefix(p)
	result[0] = 6
	if p.Addr().Is4() {
		result[0] = 4
	}
	first, last := r.From().As16(), r.To().As16()
	copy(result[1:17], first[:])
	copy(result[17:], last[:])
	return result, nil
}
func (r diskRange) addresses() (netip.Addr, netip.Addr) {
	var first, last [16]byte
	copy(first[:], r[1:17])
	copy(last[:], r[17:])
	a, b := netip.AddrFrom16(first), netip.AddrFrom16(last)
	if r[0] == 4 {
		a, b = a.Unmap(), b.Unmap()
	}
	return a, b
}
func sourcePath(dir, id, generation string) string {
	hash := sha256.Sum256([]byte(id + "\n" + generation))
	return filepath.Join(dir, "bulk", "src-"+hex.EncodeToString(hash[:])+".ranges")
}
func bulkAdmission(dir string, extra int64) error {
	var size int64
	err := filepath.WalkDir(filepath.Join(dir, "bulk"), func(_ string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("firewall bulk directory contains a symbolic link")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	if size+extra > bulkDiskLimit {
		return errors.New("firewall bulk disk capacity exceeded")
	}
	return bulkFreeSpace(filepath.Join(dir, "bulk"), extra)
}
func appendSourceRecords(ctx context.Context, dir, path string, prefixes []string) (result error) {
	if err := bulkAdmission(dir, int64(len(prefixes))*rangeBytes); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, f.Truncate(info.Size()), f.Sync())
		}
		result = errors.Join(result, f.Close())
	}()
	buffer := make([]byte, 0, rangeBytes*256)
	flush := func() error { _, err := f.Write(buffer); buffer = buffer[:0]; return err }
	for _, raw := range prefixes {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := prefixRecord(raw)
		if err != nil {
			return err
		}
		buffer = append(buffer, r[:]...)
		if len(buffer) >= rangeBytes*256 {
			if err = flush(); err != nil {
				return err
			}
		}
	}
	if err = flush(); err != nil {
		return err
	}
	return f.Sync()
}
func readRange(input io.Reader) (diskRange, error) {
	var r diskRange
	_, err := io.ReadFull(input, r[:])
	if err == nil && r[0] != 4 && r[0] != 6 {
		err = errors.New("invalid firewall range record")
	}
	if err == nil && bytes.Compare(r[1:17], r[17:]) > 0 {
		err = errors.New("invalid firewall range order")
	}
	return r, err
}
func rangeContains(path string, ip netip.Addr) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size()%rangeBytes != 0 {
		return false, errors.New("truncated firewall ranges")
	}
	family := byte(6)
	if ip.Is4() {
		family = 4
	}
	address := ip.As16()
	lo, hi := int64(0), info.Size()/rangeBytes
	for lo < hi {
		mid := (lo + hi) / 2
		var r diskRange
		if _, err = f.ReadAt(r[:], mid*rangeBytes); err != nil {
			return false, err
		}
		if r[0] < family || r[0] == family && bytes.Compare(r[1:17], address[:]) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return false, nil
	}
	var r diskRange
	if _, err = f.ReadAt(r[:], (lo-1)*rangeBytes); err != nil {
		return false, err
	}
	return r[0] == family && bytes.Compare(r[17:], address[:]) >= 0, nil
}
