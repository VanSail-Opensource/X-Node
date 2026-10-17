package firewall

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

func kernelChange(record journalRecord) bool {
	return len(record.Bans)+len(record.Exemptions)+len(record.Remove)+len(record.RemoveExemptions)+len(record.ExpiredSources)+len(record.BaseExpiredSources) > 0
}
func (g *Guard) appendJournal(record journalRecord) error {
	if err := g.flushPending(); err != nil {
		return err
	}
	record.Epoch = g.state.JournalEpoch
	record.Revision = g.state.Revision
	record.NextEvent = g.state.NextEvent
	record.SourceRevision = g.state.SourceRevision
	if len(record.BaseExpiredSources)+len(record.ExpiredSources) > 0 {
		record.SourceRevision++
	}
	if kernelChange(record) {
		record.Revision++
	}
	for i := range record.Events {
		if record.NextEvent >= 1<<63-1 {
			return errors.New("firewall event sequence exhausted")
		}
		record.NextEvent++
		record.Events[i].ID = fmt.Sprintf("%s-%020d", g.state.EventNamespace, record.NextEvent)
	}
	if err := g.appendPrepared(record); err != nil {
		g.pendingJournal = &record
		return err
	}
	return nil
}
func (g *Guard) flushPending() error {
	if g.pendingJournal == nil {
		return nil
	}
	record := *g.pendingJournal
	if err := g.appendPrepared(record); err != nil {
		return err
	}
	g.pendingJournal = nil
	return nil
}
func (g *Guard) appendPrepared(record journalRecord) error {
	release, err := g.diskLock()
	if err != nil {
		return err
	}
	defer release()
	if !g.haveSnapshot {
		if err = g.writeSnapshot(g.state); err != nil {
			return err
		}
	}
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if err = json.NewEncoder(writer).Encode(record); err != nil {
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	file, err := os.OpenFile(g.file("bans.journal.gz"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	n, writeErr := file.Write(buffer.Bytes())
	if writeErr == nil && n != buffer.Len() {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	if err = errors.Join(writeErr, syncErr); err != nil {
		truncateErr := file.Truncate(info.Size())
		closeErr := file.Close()
		return errors.Join(err, truncateErr, closeErr)
	}
	if err = file.Close(); err != nil {
		return err
	}
	g.applyRecord(record)
	g.journalBytes = info.Size() + int64(buffer.Len())
	if kernelChange(record) {
		g.dirty = true
	}
	return nil
}
