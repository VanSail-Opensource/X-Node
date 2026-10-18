package firewall

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func (g *Guard) diskLock() (func(), error) {
	if err := os.MkdirAll(g.dir, 0700); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	release, err := lockContext(ctx, g.file("bans.lock"))
	cancel()
	return release, err
}
func (g *Guard) load() error {
	release, err := g.diskLock()
	if err != nil {
		return err
	}
	defer release()
	file, err := os.Open(g.file("bans.json.gz"))
	if err == nil {
		reader, e := gzip.NewReader(file)
		if e != nil {
			_ = file.Close()
			return e
		}
		decoder := json.NewDecoder(io.LimitReader(reader, maxBanStateBytes+1))
		e = g.decodeBanState(decoder)
		if e == nil {
			_, e = io.Copy(io.Discard, reader)
		}
		closeErr := errors.Join(reader.Close(), file.Close())
		if e = errors.Join(e, closeErr); e != nil {
			return e
		}
		if g.state.Bans == nil || g.state.Exemptions == nil || g.state.Sources == nil || g.state.Events == nil || !protocol.ValidName(g.state.EventNamespace) || !protocol.ValidName(g.state.JournalEpoch) {
			return errors.New("invalid persisted firewall state")
		}
		g.haveSnapshot = true
	} else if !os.IsNotExist(err) {
		return err
	}
	return g.loadJournal()
}
func (g *Guard) loadJournal() error {
	file, err := os.OpenFile(g.file("bans.journal.gz"), os.O_RDWR, 0600)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if !g.haveSnapshot {
		return errors.New("firewall journal has no durable base snapshot")
	}
	reader := bufio.NewReader(file)
	var valid int64
	for {
		member, err := gzip.NewReader(reader)
		if err == io.EOF {
			g.journalBytes = valid
			return nil
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return g.truncateJournal(file, valid)
			}
			return err
		}
		member.Multistream(false)
		raw, readErr := io.ReadAll(io.LimitReader(member, 16<<20+1))
		closeErr := member.Close()
		if err = errors.Join(readErr, closeErr); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return g.truncateJournal(file, valid)
			}
			return err
		}
		if len(raw) > 16<<20 {
			return errors.New("firewall journal member exceeds limit")
		}
		var record journalRecord
		if err = json.Unmarshal(raw, &record); err != nil {
			return err
		}
		if record.Epoch == g.state.JournalEpoch {
			g.applyRecord(record)
		}
		offset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		valid = offset - int64(reader.Buffered())
	}
}
func (g *Guard) truncateJournal(file *os.File, valid int64) error {
	if err := file.Truncate(valid); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	g.journalBytes = valid
	return nil
}
func (g *Guard) writeSnapshot(value banState) error {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := state.AtomicWrite(g.file("bans.json.gz"), buffer.Bytes(), 0600); err != nil {
		return err
	}
	g.haveSnapshot = true
	return nil
}
func (g *Guard) compact() error {
	if err := g.flushPending(); err != nil {
		return err
	}
	if g.legacySources && g.sourceUpgradePending() {
		return errors.New("source migration awaits update confirmation")
	}
	release, err := g.diskLock()
	if err != nil {
		return err
	}
	defer release()
	next := g.state
	next.JournalEpoch = state.ID()
	if len(next.Sources) > 0 {
		if err = state.AtomicWrite(g.file("disk-sources-v1"), []byte("v1\n"), 0600); err != nil {
			return err
		}
	}
	if err = g.writeSnapshot(next); err != nil {
		return err
	}
	g.state.JournalEpoch = next.JournalEpoch
	if err = os.Remove(g.file("bans.journal.gz")); err != nil && !os.IsNotExist(err) {
		return err
	}
	g.journalBytes = 0
	g.compacted = time.Now()
	g.legacySources = false
	return nil
}
