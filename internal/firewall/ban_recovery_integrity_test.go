package firewall

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBanCheckpointRejectsIncompleteAndAmbiguousRecoveryEvidence(t *testing.T) {
	valid, err := json.Marshal(emptyBans())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(valid, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "event_namespace")
	missingNamespace, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"empty":             []byte(`{}`),
		"missing_namespace": missingNamespace,
		"duplicate_epoch":   []byte(strings.Replace(string(valid), `"journal_epoch":`, `"journal_epoch":"other","journal_epoch":`, 1)),
		"second_document":   append(append([]byte{}, valid...), []byte(`{}`)...),
		"trailing_garbage":  append(append([]byte{}, valid...), []byte("corrupt")...),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			var compressed bytes.Buffer
			writer := gzip.NewWriter(&compressed)
			if _, err := writer.Write(raw); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "bans.json.gz")
			if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenGuard(dir, nil); err == nil {
				t.Error("malformed checkpoint appeared to be usable firewall state")
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, compressed.Bytes()) {
				t.Fatal("invalid checkpoint evidence was changed", err)
			}
		})
	}
}

func TestBanCheckpointBoundIncludesTrailingWhitespace(t *testing.T) {
	raw, err := json.Marshal(emptyBans())
	if err != nil {
		t.Fatal(err)
	}
	const limit = 4096
	input := bytes.NewReader(append(raw, bytes.Repeat([]byte(" "), limit*8)...))
	before := input.Len()
	g := &Guard{}
	if err = g.decodeBanSnapshot(input, limit); err == nil {
		t.Fatal("oversized checkpoint trailing data bypassed the read bound")
	}
	if before-input.Len() > limit+1 {
		t.Fatal("checkpoint recovery drained unbounded trailing data")
	}
}
