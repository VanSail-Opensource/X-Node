package compute

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

func Encode(out Results) ([]byte, error) {
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResultBytes {
		return nil, errors.New("calculation result exceeds limit")
	}
	w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return nil, err
	}
	defer w.Close()
	compressed := w.EncodeAll(raw, nil)
	if len(compressed) > MaxCompressedBytes {
		return nil, errors.New("compressed result exceeds limit")
	}
	return compressed, nil
}

func Decode(raw []byte) (Results, error) {
	if len(raw) == 0 || len(raw) > MaxCompressedBytes {
		return Results{}, errors.New("compressed result exceeds limit")
	}
	r, err := zstd.NewReader(bytes.NewReader(raw), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(8<<20), zstd.WithDecoderMaxWindow(4<<20))
	if err != nil {
		return Results{}, err
	}
	defer r.Close()
	bounded, err := io.ReadAll(io.LimitReader(r, MaxResultBytes+1))
	if err != nil {
		return Results{}, err
	}
	if len(bounded) > MaxResultBytes {
		return Results{}, errors.New("result decompression exceeds limit")
	}
	var out Results
	d := json.NewDecoder(bytes.NewReader(bounded))
	d.DisallowUnknownFields()
	if err = d.Decode(&out); err != nil {
		return out, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return Results{}, errors.New("trailing result data")
	}
	return out, nil
}
