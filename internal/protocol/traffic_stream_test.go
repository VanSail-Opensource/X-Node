package protocol

import "testing"

func TestTrafficIdentitySeparatesLegacyAndBootSequences(t *testing.T) {
	stream := "11111111111111111111111111111111"
	for _, test := range []struct {
		id, boot string
		valid    bool
	}{
		{"agent:1", "", true}, {"agent:" + stream + ":1", stream, true},
		{"agent:01", "", false}, {"agent:0", "", false},
		{"agent:9223372036854775808", "", false}, {"other:1", "", false},
		{"agent:1", stream, false}, {"agent:" + stream + ":1", "", false},
		{"agent:invalid:1", "invalid", false},
	} {
		t.Run(test.id+test.boot, func(t *testing.T) {
			sequence, err := TrafficSequence("agent", TrafficReport{ID: test.id, StreamID: test.boot})
			if (err == nil) != test.valid || test.valid && sequence != 1 {
				t.Fatal("traffic identity mismatch", sequence, err)
			}
		})
	}
}
