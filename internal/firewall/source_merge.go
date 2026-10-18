package firewall

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"errors"
	"io"
	"os"
	"sort"
)

type rangeCursor struct {
	record diskRange
	reader *bufio.Reader
}
type rangeHeap []*rangeCursor

func (h rangeHeap) Len() int           { return len(h) }
func (h rangeHeap) Less(i, j int) bool { return bytes.Compare(h[i].record[:], h[j].record[:]) < 0 }
func (h rangeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *rangeHeap) Push(v any)        { *h = append(*h, v.(*rangeCursor)) }
func (h *rangeHeap) Pop() any          { old := *h; v := old[len(old)-1]; *h = old[:len(old)-1]; return v }

// mergeRangeFiles retains one record per run and coalesces overlaps/adjacency.
func mergeRangeFiles(ctx context.Context, paths []string, visit func(diskRange) error) error {
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	queue := rangeHeap{}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		files = append(files, f)
		r := bufio.NewReaderSize(f, 4096)
		record, err := readRange(r)
		if errors.Is(err, io.EOF) {
			continue
		}
		if err != nil {
			return err
		}
		heap.Push(&queue, &rangeCursor{record: record, reader: r})
	}
	var previous diskRange
	have := false
	for queue.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor := heap.Pop(&queue).(*rangeCursor)
		current := cursor.record
		if have {
			_, last := previous.addresses()
			first, _ := current.addresses()
			if current[0] == previous[0] && (first.Compare(last) <= 0 || first == last.Next()) {
				if bytes.Compare(current[17:], previous[17:]) > 0 {
					copy(previous[17:], current[17:])
				}
			} else {
				if err := visit(previous); err != nil {
					return err
				}
				previous = current
			}
		} else {
			previous = current
			have = true
		}
		next, err := readRange(cursor.reader)
		if err == nil {
			cursor.record = next
			heap.Push(&queue, cursor)
		} else if !errors.Is(err, io.EOF) {
			return err
		}
	}
	if have {
		return visit(previous)
	}
	return nil
}

// sortSourceRecords bounds the sort buffer to roughly one MiB, independently of
// feed size. Run files and output count against the same disk admission budget.
func sortSourceRecords(ctx context.Context, dir, input, output string) error {
	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var runs []string
	defer func() {
		for _, path := range runs {
			_ = os.Remove(path)
		}
	}()
	for {
		buffer := make([]diskRange, 0, 32768)
		for len(buffer) < cap(buffer) {
			record, e := readRange(r)
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				return e
			}
			buffer = append(buffer, record)
		}
		if len(buffer) == 0 {
			break
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		sort.Slice(buffer, func(i, j int) bool { return bytes.Compare(buffer[i][:], buffer[j][:]) < 0 })
		if err = bulkAdmission(dir, int64(len(buffer))*rangeBytes); err != nil {
			return err
		}
		run, e := os.CreateTemp(dir+string(os.PathSeparator)+"bulk", "sort-*")
		if e != nil {
			return e
		}
		runs = append(runs, run.Name())
		w := bufio.NewWriter(run)
		for _, record := range buffer {
			if _, err = w.Write(record[:]); err != nil {
				_ = run.Close()
				return err
			}
		}
		err = errors.Join(w.Flush(), run.Close())
		if err != nil {
			return err
		}
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err = bulkAdmission(dir, info.Size()); err != nil {
		return err
	}
	out, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	err = mergeRangeFiles(ctx, runs, func(record diskRange) error { _, e := w.Write(record[:]); return e })
	err = errors.Join(err, w.Flush(), out.Sync(), out.Close())
	if err != nil {
		_ = os.Remove(output)
	}
	return err
}
