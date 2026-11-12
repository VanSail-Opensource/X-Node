package agent

import (
	"encoding/json/jsontext"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	legacyJobRecoveryMaxBytes   = 16 << 20
	legacyJobRecoveryMaxRecords = 128
)

var errLegacyJobMetadata = errors.New("invalid legacy job journal metadata")

type jobRecoveryReader struct {
	reader io.Reader
	failed bool
}

func (r *jobRecoveryReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if err != nil && err != io.EOF {
		r.failed = true
	}
	return n, err
}

// readLegacyJobMetadata recovers identities without retaining result payloads.
// The whole input, including whitespace, is capped at 16 MiB: jsontext streams
// containers but may buffer one scalar token, so a larger recovery cap would
// jeopardize the agent's 256 MiB budget. The caller preserves the source file
// and decides which recovered mutations must remain uncertain.
func readLegacyJobMetadata(reader io.Reader) ([]JobResult, error) {
	tracked := &jobRecoveryReader{reader: reader}
	limited := &io.LimitedReader{R: tracked, N: legacyJobRecoveryMaxBytes + 1}
	decoder := jsontext.NewDecoder(limited, jsontext.AllowDuplicateNames(true))
	first, err := decoder.ReadToken()
	if err != nil {
		return nil, errLegacyJobMetadata
	}
	var results []JobResult
	switch first.Kind() {
	case 'n': // Old json.Marshal(nilSlice) wrote null.
	case '[':
		seen := make(map[string]struct{})
		for decoder.PeekKind() != ']' {
			if len(results) >= legacyJobRecoveryMaxRecords {
				return nil, errLegacyJobMetadata
			}
			result, err := readLegacyJobRecord(decoder)
			if err != nil {
				return nil, err
			}
			if _, duplicate := seen[result.ID]; duplicate {
				return nil, errLegacyJobMetadata
			}
			seen[result.ID] = struct{}{}
			results = append(results, result)
		}
		if end, err := decoder.ReadToken(); err != nil || end.Kind() != ']' {
			return nil, errLegacyJobMetadata
		}
	default:
		return nil, errLegacyJobMetadata
	}
	// Consuming through EOF makes trailing whitespace part of the byte budget
	// and rejects a second JSON value, malformed suffix or interrupted input.
	if _, err := decoder.ReadToken(); err != io.EOF || limited.N == 0 || tracked.failed {
		return nil, errLegacyJobMetadata
	}
	return results, nil
}

func readLegacyJobRecord(decoder *jsontext.Decoder) (JobResult, error) {
	var result JobResult
	if start, err := decoder.ReadToken(); err != nil || start.Kind() != '{' {
		return result, errLegacyJobMetadata
	}
	var seen uint8
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil || key.Kind() != '"' {
			return JobResult{}, errLegacyJobMetadata
		}
		var field uint8
		var maximum int
		for _, name := range []string{"id", "command", "status", "finished", "terminal_failure"} {
			if key.String() != name && strings.EqualFold(key.String(), name) {
				return JobResult{}, errLegacyJobMetadata
			}
		}
		switch key.String() {
		case "id":
			field, maximum = 1, 128
		case "command":
			field, maximum = 2, 64
		case "status":
			field, maximum = 4, 32
		case "finished":
			field, maximum = 8, 64
		case "terminal_failure":
			field = 16
		default:
			if err := decoder.SkipValue(); err != nil {
				return JobResult{}, errLegacyJobMetadata
			}
			continue
		}
		if seen&field != 0 {
			return JobResult{}, errLegacyJobMetadata
		}
		seen |= field
		token, err := decoder.ReadToken()
		if field == 16 {
			if err != nil || token.Kind() != 't' && token.Kind() != 'f' {
				return JobResult{}, errLegacyJobMetadata
			}
			result.terminalFailure = token.Kind() == 't'
			continue
		}
		if err != nil || token.Kind() != '"' {
			return JobResult{}, errLegacyJobMetadata
		}
		value := token.String()
		if len(value) == 0 || len(value) > maximum || strings.ContainsAny(value, "\x00\r\n") {
			return JobResult{}, errLegacyJobMetadata
		}
		switch field {
		case 1:
			result.ID = value
		case 2:
			result.Command = value
		case 4:
			switch value {
			case "completed", "failed", "cancelled", "uncertain", "running":
				result.Status = value
			default:
				return JobResult{}, errLegacyJobMetadata
			}
		case 8:
			result.Finished, err = time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return JobResult{}, errLegacyJobMetadata
			}
		}
	}
	if end, err := decoder.ReadToken(); err != nil || end.Kind() != '}' || seen&7 != 7 {
		return JobResult{}, errLegacyJobMetadata
	}
	if result.terminalFailure && result.Status != "failed" {
		return JobResult{}, errLegacyJobMetadata
	}
	return result, nil
}
