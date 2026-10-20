package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
)

const sourceLookupBytes = 32 << 20
const lookupBlockRecords = 256

type sourceLookup struct {
	id        string
	file      *os.File
	count     int64
	ranges    []diskRange
	blocks    []diskRange
	err       error
	page      []diskRange
	pageStart int64
}

func (g *Guard) closeSourceLookups() {
	for _, lookup := range g.lookups {
		if lookup.file != nil {
			_ = lookup.file.Close()
		}
	}
	g.lookups = nil
	g.lookupRevision = 0
}

// Revisions invalidate both resident ranges and file metadata. Large sources
// retain a sparse block index: lookup uses one bounded ReadAt, never Open/Stat.
func (g *Guard) rebuildSourceLookups() {
	if g.lookups != nil && g.lookupRevision == g.state.SourceRevision {
		return
	}
	g.closeSourceLookups()
	g.lookupRevision = g.state.SourceRevision
	g.lookups = make([]sourceLookup, 0, len(g.state.Sources))
	ids := make([]string, 0, len(g.state.Sources))
	for id := range g.state.Sources {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	remaining := int64(sourceLookupBytes)
	sparse := int64(4 << 20)
	for _, id := range ids {
		source := g.state.Sources[id]
		if source.Expired {
			continue
		}
		lookup := sourceLookup{id: id}
		lookup.err = lookup.open(sourcePath(g.dir, id, source.Generation), &remaining, &sparse)
		g.lookups = append(g.lookups, lookup)
	}
}

func (l *sourceLookup) open(path string, budget, sparse *int64) (result error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if result != nil || l.file == nil {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size()%rangeBytes != 0 {
		return errors.New("truncated firewall ranges")
	}
	l.count = info.Size() / rangeBytes
	l.pageStart = -1
	if info.Size() <= *budget {
		l.ranges = make([]diskRange, l.count)
		reader := bufio.NewReaderSize(f, 64<<10)
		for i := range l.ranges {
			if l.ranges[i], err = readRange(reader); err != nil {
				return err
			}
		}
		*budget -= info.Size()
		return nil
	}
	// The sparse index remains bounded even if metadata describes a huge file.
	blocks := (l.count + lookupBlockRecords - 1) / lookupBlockRecords
	if blocks*rangeBytes > *sparse {
		return errors.New("firewall lookup capacity exceeded")
	}
	*sparse -= blocks * rangeBytes
	l.blocks = make([]diskRange, blocks)
	for i := range l.blocks {
		if _, err = f.ReadAt(l.blocks[i][:], int64(i)*lookupBlockRecords*rangeBytes); err != nil {
			return err
		}
	}
	l.file = f
	return nil
}

func rangeBefore(r diskRange, family byte, address []byte) bool {
	return r[0] < family || r[0] == family && bytes.Compare(r[1:17], address) <= 0
}

func containsRange(ranges []diskRange, family byte, address []byte) bool {
	i := sort.Search(len(ranges), func(i int) bool { return !rangeBefore(ranges[i], family, address) })
	return i > 0 && ranges[i-1][0] == family && bytes.Compare(ranges[i-1][17:], address) >= 0
}

func (l *sourceLookup) contains(ip netip.Addr) (bool, error) {
	if l.err != nil {
		return false, l.err
	}
	family, address := byte(6), ip.As16()
	if ip.Is4() {
		family = 4
	}
	if l.file == nil {
		return containsRange(l.ranges, family, address[:]), nil
	}
	i := sort.Search(len(l.blocks), func(i int) bool { return !rangeBefore(l.blocks[i], family, address[:]) })
	if i == 0 {
		return false, nil
	}
	start := int64(i-1) * lookupBlockRecords
	count := min(int64(lookupBlockRecords), l.count-start)
	if l.pageStart == start {
		return containsRange(l.page, family, address[:]), nil
	}
	if l.page == nil {
		l.page = make([]diskRange, lookupBlockRecords)
	}
	l.page = l.page[:count]
	// diskRange has no padding; keep serialization explicit rather than unsafe.
	var raw [lookupBlockRecords * rangeBytes]byte
	n, err := l.file.ReadAt(raw[:count*rangeBytes], start*rangeBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	if int64(n) != count*rangeBytes {
		return false, io.ErrUnexpectedEOF
	}
	for j := range count {
		copy(l.page[j][:], raw[j*rangeBytes:(j+1)*rangeBytes])
	}
	l.pageStart = start
	return containsRange(l.page, family, address[:]), nil
}
