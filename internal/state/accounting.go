package state

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// AddAccounting commits legacy totals and period samples in one durable mutation.
func (s *Store) AddAccounting(delta Traffic, samples []protocol.TrafficSample) error {
	if len(delta) == 0 && len(samples) == 0 {
		return nil
	}
	return s.change(func(d *Data) error {
		if err := addTraffic(d, delta); err != nil {
			return err
		}
		if d.Accounting == nil {
			d.Accounting = map[string]protocol.TrafficSample{}
		}
		for _, sample := range samples {
			if sample.UserID <= 0 || !protocol.ValidName(sample.AccountingPeriod) || sample.From.IsZero() || sample.Through.Before(sample.From) {
				return errors.New("invalid accounting sample")
			}
			key := fmt.Sprintf("%d:%s:%s", sample.UserID, sample.AccountingPeriod, sample.Through.UTC().Format(time.DateOnly))
			old, exists := d.Accounting[key]
			if !exists {
				d.Accounting[key] = sample
				continue
			}
			if ^uint64(0)-old.UploadBytes < sample.UploadBytes || ^uint64(0)-old.DownloadBytes < sample.DownloadBytes {
				return errors.New("accounting counter overflow")
			}
			old.UploadBytes += sample.UploadBytes
			old.DownloadBytes += sample.DownloadBytes
			if sample.From.Before(old.From) {
				old.From = sample.From
			}
			if sample.Through.After(old.Through) {
				old.Through = sample.Through
			}
			d.Accounting[key] = old
		}
		return nil
	})
}

func addTraffic(d *Data, delta Traffic) error {
	if d.Accumulated == nil {
		d.Accumulated = Traffic{}
	}
	for id, bytes := range delta {
		old := d.Accumulated[id]
		if ^uint64(0)-old[0] < bytes[0] || ^uint64(0)-old[1] < bytes[1] {
			return errors.New("traffic counter overflow")
		}
		d.Accumulated[id] = [2]uint64{old[0] + bytes[0], old[1] + bytes[1]}
	}
	return nil
}

func sealTraffic(d *Data) error {
	if len(d.Accumulated) == 0 && len(d.Accounting) == 0 {
		return nil
	}
	if d.Sequence == ^uint64(0) {
		return errors.New("traffic sequence exhausted")
	}
	d.Sequence++
	batch := &Batch{ID: fmt.Sprintf("%s:%d", d.AgentID, d.Sequence), Traffic: d.Accumulated}
	keys := make([]string, 0, len(d.Accounting))
	for key := range d.Accounting {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		batch.Samples = append(batch.Samples, d.Accounting[key])
	}
	d.Accumulated = Traffic{}
	d.Accounting = nil
	if d.Pending == nil {
		d.Pending = batch
	} else {
		d.Backlog = append(d.Backlog, batch)
	}
	return nil
}

// Flush seals all captured data without replacing an outstanding replay batch.
func (s *Store) Flush() (protocol.TrafficBarrier, error) {
	var barrier protocol.TrafficBarrier
	err := s.change(func(d *Data) error {
		if err := sealTraffic(d); err != nil {
			return err
		}
		barrier = protocol.TrafficBarrier{AgentID: d.AgentID, Sequence: d.Sequence, Through: time.Now().UTC()}
		return nil
	})
	return barrier, err
}
