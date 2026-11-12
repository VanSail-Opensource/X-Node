package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

const legacyJobMetadataFixture = `{"id":"mutation","command":"update.install","status":"running","finished":"2026-11-08T11:10:00.123456789Z"}`

func TestLegacyJobRecoveryDiscardsLargeNestedResults(t *testing.T) {
	data := `[{"id":"read","command":"firewall.status","status":"completed","data":{"nested":[` +
		strings.Repeat(`{"source_ip":"192.0.2.1","duplicate":1,"duplicate":2},`, 70000) +
		`null]}},` + legacyJobMetadataFixture[:len(legacyJobMetadataFixture)-1] + `,"data":{"private":"discard"},"error":"discard","future":[{"large":"discard"}]}]`
	results, err := readLegacyJobMetadata(strings.NewReader(data))
	if err != nil || len(results) != 2 {
		t.Fatalf("metadata recovery failed: %v, %d results", err, len(results))
	}
	if results[0].ID != "read" || results[0].Command != "firewall.status" || results[0].Status != "completed" ||
		results[1].ID != "mutation" || results[1].Command != "update.install" || results[1].Status != "running" {
		t.Fatal("receipt identities or original status changed")
	}
	want := time.Date(2026, 11, 8, 11, 10, 0, 123456789, time.UTC)
	if !results[1].Finished.Equal(want) {
		t.Fatal("completion timestamp changed")
	}
	for _, result := range results {
		if result.Data != nil || result.Error != "" {
			t.Fatal("recovery retained private result data")
		}
	}
}

func TestLegacyJobRecoveryDiscardsLargeScalar(t *testing.T) {
	data := `[` + legacyJobMetadataFixture[:len(legacyJobMetadataFixture)-1] + `,"data":"` + strings.Repeat("x", 3<<20) + `"}]`
	results, err := readLegacyJobMetadata(strings.NewReader(data))
	if err != nil || len(results) != 1 || results[0].Data != nil {
		t.Fatalf("large scalar recovery failed: %v", err)
	}
}

func TestLegacyJobRecoveryCountsAllInputBytes(t *testing.T) {
	for _, test := range []struct {
		name, input string
		valid       bool
	}{
		{"exact limit", "[]" + strings.Repeat(" ", legacyJobRecoveryMaxBytes-2), true},
		{"leading whitespace", strings.Repeat(" ", legacyJobRecoveryMaxBytes) + "[]", false},
		{"trailing whitespace", "[]" + strings.Repeat(" ", legacyJobRecoveryMaxBytes-1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readLegacyJobMetadata(strings.NewReader(test.input))
			if (err == nil) != test.valid {
				t.Fatalf("byte limit result: %v", err)
			}
		})
	}
}

func TestLegacyJobRecoveryRejectsAmbiguousOrMalformedMetadata(t *testing.T) {
	for _, test := range []struct{ name, input string }{
		{"duplicate id field", `[{"id":"a","id":"b","command":"runtime.reload","status":"completed"}]`},
		{"duplicate command", `[{"id":"a","command":"runtime.reload","command":"update.install","status":"completed"}]`},
		{"case folded command", `[{"id":"a","command":"firewall.status","Command":"runtime.reload","status":"completed"}]`},
		{"duplicate status", `[{"id":"a","command":"runtime.reload","status":"completed","status":"running"}]`},
		{"duplicate terminal evidence", `[{"id":"a","command":"runtime.reload","status":"failed","terminal_failure":false,"terminal_failure":true}]`},
		{"case folded terminal evidence", `[{"id":"a","command":"runtime.reload","status":"failed","Terminal_Failure":true}]`},
		{"nonboolean terminal evidence", `[{"id":"a","command":"runtime.reload","status":"failed","terminal_failure":"true"}]`},
		{"contradictory terminal evidence", `[{"id":"a","command":"runtime.reload","status":"uncertain","terminal_failure":true}]`},
		{"duplicate finished", `[{"id":"a","command":"runtime.reload","status":"completed","finished":"2026-11-08T00:00:00Z","finished":"2026-11-09T00:00:00Z"}]`},
		{"duplicate receipts", `[` + legacyJobMetadataFixture + `,` + legacyJobMetadataFixture + `]`},
		{"missing id", `[{"command":"runtime.reload","status":"completed"}]`},
		{"missing command", `[{"id":"a","status":"completed"}]`},
		{"missing status", `[{"id":"a","command":"runtime.reload"}]`},
		{"wrong id type", `[{"id":1,"command":"runtime.reload","status":"completed"}]`},
		{"wrong command type", `[{"id":"a","command":null,"status":"completed"}]`},
		{"unknown status", `[{"id":"a","command":"runtime.reload","status":"successful"}]`},
		{"invalid timestamp", `[{"id":"a","command":"runtime.reload","status":"completed","finished":"yesterday"}]`},
		{"non-string timestamp", `[{"id":"a","command":"runtime.reload","status":"completed","finished":null}]`},
		{"truncated payload", `[{"id":"a","command":"runtime.reload","status":"completed","data":[1,`},
		{"truncated record", `[{"id":"a","command":"runtime.reload","status":"completed"`},
		{"trailing value", `[` + legacyJobMetadataFixture + `] []`},
		{"trailing garbage", `[` + legacyJobMetadataFixture + `] !`},
		{"null with suffix", `null []`},
		{"wrong root", `{}`},
		{"null record", `[null]`},
		{"missing input", ``},
	} {
		t.Run(test.name, func(t *testing.T) {
			if results, err := readLegacyJobMetadata(strings.NewReader(test.input)); err == nil || results != nil {
				t.Fatal("accepted or partially returned an ambiguous journal")
			}
		})
	}
}

func TestLegacyJobRecoveryBoundsReceiptCountAndIdentifiers(t *testing.T) {
	for _, count := range []int{legacyJobRecoveryMaxRecords, legacyJobRecoveryMaxRecords + 1} {
		results := make([]JobResult, count)
		for i := range results {
			results[i] = JobResult{ID: fmt.Sprint(i), Command: "runtime.reload", Status: "uncertain"}
		}
		raw, err := json.Marshal(results)
		if err != nil {
			t.Fatal(err)
		}
		got, err := readLegacyJobMetadata(strings.NewReader(string(raw)))
		if (err == nil) != (count == legacyJobRecoveryMaxRecords) || err == nil && len(got) != count {
			t.Fatalf("record count %d: %v", count, err)
		}
	}
	for _, test := range []struct {
		id, command, status string
		valid               bool
	}{
		{strings.Repeat("i", 128), strings.Repeat("c", 64), "failed", true},
		{strings.Repeat("i", 129), "runtime.reload", "completed", false},
		{"a", strings.Repeat("c", 65), "completed", false},
		{"a", "runtime.reload", strings.Repeat("s", 33), false},
		{"", "runtime.reload", "completed", false},
		{"a", "", "completed", false},
		{"a\n", "runtime.reload", "completed", false},
	} {
		raw, err := json.Marshal([]JobResult{{ID: test.id, Command: test.command, Status: test.status}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = readLegacyJobMetadata(strings.NewReader(string(raw)))
		if (err == nil) != test.valid {
			t.Fatalf("identifier bounds: %v", err)
		}
	}
}

func TestLegacyJobRecoveryAcceptsOnlyCompleteEmptyDocuments(t *testing.T) {
	for _, input := range []string{"null", " \nnull\t", "[]"} {
		results, err := readLegacyJobMetadata(strings.NewReader(input))
		if err != nil || len(results) != 0 {
			t.Fatalf("empty document rejected: %v", err)
		}
	}
}

func TestLegacyJobRecoveryRejectsReadFailureAfterCompleteJSON(t *testing.T) {
	reader := io.MultiReader(strings.NewReader("["+legacyJobMetadataFixture+"]"), iotest.ErrReader(errors.New("synthetic read failure")))
	if results, err := readLegacyJobMetadata(reader); err == nil || results != nil {
		t.Fatal("partial I/O was accepted as complete recovery")
	}
}
