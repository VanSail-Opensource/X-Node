package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (g *Guard) migrateSource(source *sourceState) error {
	if len(source.Prefixes) == 0 {
		return nil
	}
	if err := os.MkdirAll(g.file("bulk"), 0700); err != nil {
		return err
	}
	path := sourcePath(g.dir, source.ID, source.Generation)
	staged, err := os.CreateTemp(g.file("bulk"), "migration-*")
	if err != nil {
		return err
	}
	name := staged.Name()
	_ = staged.Close()
	defer os.Remove(name)
	if err = appendSourceRecords(context.Background(), g.dir, name, source.Prefixes); err != nil {
		return err
	}
	if err = g.migrateSourceFile(source, name, path); err != nil {
		return err
	}
	source.Prefixes = nil
	return nil
}
func (g *Guard) migrateSourceFile(source *sourceState, input, target string) error {
	if !protocol.ValidName(source.ID) || !protocol.ValidName(source.Generation) {
		return errors.New("invalid persisted source identity")
	}
	if err := sortSourceRecords(context.Background(), g.dir, input, input+".sorted"); err != nil {
		return err
	}
	defer os.Remove(input + ".sorted")
	if err := publishRangeFile(input+".sorted", target); err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	source.PrefixCount = int(info.Size() / rangeBytes)
	return nil
}

// decodeBanState upgrades the old gzip format without materializing its sources.
func (g *Guard) decodeBanState(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid firewall state")
	}
	fields := map[string]any{"source_master_version": &g.state.SourceMasterVersion, "source_revision": &g.state.SourceRevision, "master_version": &g.state.MasterVersion, "event_namespace": &g.state.EventNamespace, "next_event": &g.state.NextEvent, "revision": &g.state.Revision, "bans": &g.state.Bans, "exemptions": &g.state.Exemptions, "events": &g.state.Events, "snapshot_id": &g.state.SnapshotID, "journal_epoch": &g.state.JournalEpoch}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		if key == "sources" {
			if err = g.decodeSources(d); err != nil {
				return err
			}
			continue
		}
		pointer, ok := fields[key.(string)]
		if !ok {
			return errors.New("unknown firewall state field")
		}
		if err = d.Decode(pointer); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
func (g *Guard) decodeSources(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid firewall sources")
	}
	g.state.Sources = map[string]sourceState{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return err
		}
		if len(g.state.Sources) >= 128 {
			return errors.New("source capacity exceeded")
		}
		source, err := g.decodeSource(d)
		if err != nil {
			return err
		}
		if source.ID != key.(string) {
			return errors.New("source identity differs")
		}
		g.state.Sources[source.ID] = source
	}
	_, err = d.Token()
	return err
}
func (g *Guard) decodeSource(d *json.Decoder) (sourceState, error) {
	source := sourceState{}
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return source, errors.New("invalid source record")
	}
	fields := map[string]any{"id": &source.ID, "generation": &source.Generation, "until": &source.Until, "refresh_seconds": &source.RefreshSeconds, "reference": &source.Reference, "expired": &source.Expired, "base_expired": &source.BaseExpired, "prefix_count": &source.PrefixCount, "previous_generation": &source.PreviousGeneration}
	var staged string
	defer func() {
		if staged != "" {
			_ = os.Remove(staged)
		}
	}()
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return source, err
		}
		if key != "prefixes" {
			pointer, ok := fields[key.(string)]
			if !ok {
				return source, errors.New("unknown source field")
			}
			if err = d.Decode(pointer); err != nil {
				return source, err
			}
			continue
		}
		token, err = d.Token()
		if err != nil {
			return source, err
		}
		if token == nil {
			continue
		}
		if token != json.Delim('[') {
			return source, errors.New("invalid source prefixes")
		}
		if err = os.MkdirAll(g.file("bulk"), 0700); err != nil {
			return source, err
		}
		file, err := os.CreateTemp(g.file("bulk"), "migration-*")
		if err != nil {
			return source, err
		}
		staged = file.Name()
		_ = file.Close()
		batch := []string{}
		for d.More() {
			var prefix string
			if err = d.Decode(&prefix); err != nil {
				return source, err
			}
			batch = append(batch, prefix)
			if len(batch) == 256 {
				if err = appendSourceRecords(context.Background(), g.dir, staged, batch); err != nil {
					return source, err
				}
				batch = batch[:0]
			}
		}
		if err = appendSourceRecords(context.Background(), g.dir, staged, batch); err != nil {
			return source, err
		}
		if _, err = d.Token(); err != nil {
			return source, err
		}
	}
	if _, err = d.Token(); err != nil {
		return source, err
	}
	if staged != "" {
		err = g.migrateSourceFile(&source, staged, sourcePath(g.dir, source.ID, source.Generation))
	}
	return source, err
}
