package protocol

import (
	"errors"
	"io"
)

// ReadMessagePayload bounds the uncompressed bytes returned by a WebSocket
// reader before JSON allocation/decoding, including compressed input expansion.
func ReadMessagePayload(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFrameBytes {
		return nil, errors.New("decompressed frame too large")
	}
	return data, nil
}
