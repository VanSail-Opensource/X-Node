package hourly

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestCorruptJournalFailsHourlyClosedAndPreservesEvidence(t *testing.T) {
	valid, err := json.Marshal(creditJournal{Version: creditJournalVersion})
	if err != nil {
		t.Fatal(err)
	}
	fixtures := map[string][]byte{
		"duplicate":  []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)),
		"case-alias": []byte(strings.Replace(string(valid), `"version":1`, `"Version":1`, 1)),
		"unknown":    []byte(strings.Replace(string(valid), `"version":1`, `"version":1,"extra":true`, 1)),
		"truncated":  valid[:len(valid)-1],
		"trailing":   append(append([]byte(nil), valid...), []byte(`{}`)...),
		"oversized":  bytes.Repeat([]byte(" "), creditJournalMaxBytes+1),
		"null":       []byte("null"),
	}
	for name, raw := range fixtures {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credit.json")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			store, err := OpenCreditStore(path)
			if !errors.Is(err, ErrCreditCorrupt) || store == nil || store.Healthy() || len(store.Recovery()) != 0 {
				t.Fatal("corrupt journal did not isolate hourly recovery", err)
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, retained) {
				t.Fatal("original journal evidence was modified", err)
			}
		})
	}
}

func TestJournalRejectsAlteredFinalProofOrHighwater(t *testing.T) {
	install := creditFixtureInstall(1)
	proof := fixtureCreditProof(install, 100)
	valid := creditJournal{Version: creditJournalVersion, AgentID: install.AgentID, HighWater: 1, Records: []creditRecord{{Install: install, Digest: protocol.HourlyInstallDigest(install), Proof: &proof}}}
	for _, kind := range []string{"digest", "binding", "partition", "highwater", "agent", "sequence"} {
		t.Run(kind, func(t *testing.T) {
			journal := valid
			journal.Records = append([]creditRecord(nil), valid.Records...)
			altered := proof
			journal.Records[0].Proof = &altered
			switch kind {
			case "digest":
				altered.Digest = strings.Repeat("0", 64)
			case "binding":
				altered.Install.Owner.Generation++
			case "partition":
				altered.UnusedBytes++
			case "highwater":
				journal.HighWater++
			case "agent":
				journal.AgentID = install.BootID
			case "sequence":
				journal.Records[0].Install.IssueSequence = 0
			}
			path := filepath.Join(t.TempDir(), "credit.json")
			writeCreditFixture(t, path, journal)
			if store, err := OpenCreditStore(path); !errors.Is(err, ErrCreditCorrupt) || store.Healthy() {
				t.Fatal("inconsistent financial evidence loaded", err)
			}
		})
	}
}

func TestJournalRefusesNonPrivateFilesAndSymlinks(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "public-file", true: "symlink"}[symlink], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credit.json")
			raw := []byte(`{"version":1,"agent_id":"","high_water":"0","records":null,"tombstones":null}`)
			if symlink {
				target := path + ".original"
				if err := os.WriteFile(target, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if store, err := OpenCreditStore(path); !errors.Is(err, ErrCreditCorrupt) || store.Healthy() {
				t.Fatal("unsafe journal path accepted", err)
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, retained) {
				t.Fatal("unsafe evidence was overwritten", err)
			}
		})
	}
}
