package protocol

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const TrafficStreamCapability = "traffic_stream_v1"
const TrafficStreamHeader = "X-XNode-Traffic"
const TrafficStreamFormat = "stream-v1"

// TrafficSequence validates canonical identities without converting stream IDs
// into legacy journal keys. Stream IDs are the authenticated process boot ID.
func TrafficSequence(agent string, report TrafficReport) (uint64, error) {
	prefix := agent + ":"
	if report.StreamID != "" {
		if !ValidStreamID(report.StreamID) {
			return 0, errors.New("invalid traffic stream")
		}
		prefix += report.StreamID + ":"
	}
	raw, ok := strings.CutPrefix(report.ID, prefix)
	sequence, err := strconv.ParseUint(raw, 10, 63)
	if !ok || err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != raw {
		return 0, errors.New("invalid traffic identity")
	}
	return sequence, nil
}

func ValidStreamID(value string) bool {
	if len(value) != 32 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
