package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCanonicalCommandArgsRetainsExactValues(t *testing.T) {
	input := []byte(`{"z":[null,true,{"b":9007199254740993,"a":[]}],"first":"value"}`)
	got, err := canonicalCommandArgs(input)
	want := `{"first":"value","z":[null,true,{"a":[],"b":9007199254740993}]}`
	if err != nil || string(got) != want {
		t.Fatalf("canonical arguments changed exact values: %s (%v)", got, err)
	}
}

func TestCanonicalCommandArgsPreservesCaseSensitiveMapsAndTypedAliasOrder(t *testing.T) {
	for _, raw := range []string{
		`{"quiesce":true,"Quiesce":false}`,
		`{"z":{"a":1,"A":2},"a":3}`,
		`{"kelvinK":1,"kelvink":2}`,
	} {
		got, err := canonicalCommandArgs([]byte(raw))
		if err != nil || string(got) != raw {
			t.Fatalf("canonicalization changed order-sensitive keys: %s (%v)", got, err)
		}
	}
	raw := []byte(`{"quiesce":true,"Quiesce":false}`)
	got, _ := canonicalCommandArgs(raw)
	var original, canonical struct{ Quiesce bool }
	if json.Unmarshal(raw, &original) != nil || json.Unmarshal(got, &canonical) != nil || original != canonical || canonical.Quiesce {
		t.Fatal("normalization changed typed command semantics")
	}
}

func TestCanonicalCommandArgsRejectsAmbiguousOrUnboundedInput(t *testing.T) {
	for _, raw := range []string{
		`{"id":1,"id":2}`,
		`{"id":1,"\u0069d":2}`,
		`{"policy":{"enabled":true},"policy":{}}`,
		`{"items":[{"bytes":1,"bytes":2}]}`,
		`{"a":null,"a":false}`,
		`{} {}`,
		`null`,
		`[]`,
		`{"broken":`,
		`{"deep":` + strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129) + "}",
	} {
		if _, err := canonicalCommandArgs([]byte(raw)); err == nil {
			t.Errorf("accepted ambiguous command arguments: %.120s", raw)
		}
	}
}
