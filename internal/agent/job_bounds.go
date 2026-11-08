package agent

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

const (
	maxJobJournalBytes = 2 << 20 // Strictly below the old loader's boundary.
	maxJobResultBytes  = 64 << 10
	maxJobHistory      = 128
)

var errJobCapacity = errors.New("job receipt capacity exhausted; uncertain identities were preserved")
var errJobSize = errors.New("job receipt byte limit exceeded")

type jobBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *jobBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errJobSize
	}
	return b.buffer.Write(p)
}

// Stream into a bounded buffer with existing v1 wire semantics. A large policy
// array cannot first allocate an unbounded complete serialized result.
func marshalJobBounded(value any, limit int) ([]byte, error) {
	buffer := &jobBuffer{limit: limit}
	if err := jsonv2.MarshalWrite(buffer, value, json.DefaultOptionsV1()); err != nil {
		return nil, err
	}
	return buffer.buffer.Bytes(), nil
}

func boundedJobResult(result JobResult) JobResult {
	return limitJobResult(result, maxJobResultBytes)
}

func wireJobResult(result JobResult) JobResult {
	return limitJobResult(result, protocol.MaxFrameBytes-4096)
}

func limitJobResult(result JobResult, limit int) JobResult {
	if len(result.Error) > 1024 {
		result.Error = strings.ToValidUTF8(result.Error[:1024], "")
	}
	if protectedJob(result) {
		result.Data = nil
	}
	raw, err := marshalJobBounded(result, limit)
	if err != nil {
		result.Data = nil
		result.Status, result.Error = "failed", "job result exceeded its safe serialization limit"
		if persistentJob(result.Command) {
			result.Status = "uncertain"
		}
		raw, _ = marshalJobBounded(result, limit)
	}
	// Keep exact native integers instead of decoding opaque data into float64.
	var payload struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &payload)
	if len(payload.Data) > 0 {
		result.Data = payload.Data
	} else {
		result.Data = nil
	}
	result.encodedBytes = len(raw)
	return result
}

func cloneJobResult(result JobResult) JobResult {
	if raw, ok := result.Data.(json.RawMessage); ok {
		result.Data = append(json.RawMessage(nil), raw...)
	}
	return result
}

// Each caller normalizes entries first. Preserve uncertain mutation identities;
// later observations cannot evict them to admit another command.
func retainJob(history []JobResult, result JobResult, protect bool) ([]JobResult, error) {
	next := make([]JobResult, 0, len(history)+1)
	for _, old := range history {
		if old.ID != result.ID {
			next = append(next, old)
		}
	}
	next = append(next, result)
	size := 1 + len(next)
	for _, entry := range next {
		size += entry.encodedBytes
	}
	for len(next) > maxJobHistory || size >= maxJobJournalBytes {
		remove := -1
		for i, entry := range next {
			if !protect || !protectedJob(entry) {
				remove = i
				break
			}
		}
		if remove < 0 || next[remove].ID == result.ID {
			return nil, errJobCapacity
		}
		size -= next[remove].encodedBytes + 1
		next = append(next[:remove], next[remove+1:]...)
	}
	return next, nil
}
