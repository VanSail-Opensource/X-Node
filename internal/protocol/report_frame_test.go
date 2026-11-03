package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReportFramesBoundExpansionAndRetainedBuffers(t *testing.T) {
	encoder, err := NewReportEncoder()
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	decoder, err := NewReportDecoder()
	if err != nil {
		t.Fatal(err)
	}
	defer decoder.Close()
	for _, raw := range [][]byte{[]byte(`{"v":1,"type":"logs.report","data":{"entries":[]}}`), bytes.Repeat([]byte("large compressible report "), 1<<16)} {
		frame, err := encoder.Encode(raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decoder.Read(bytes.NewReader(frame))
		if err != nil || !bytes.Equal(decoded, raw) {
			t.Fatal("report changed", err)
		}
		if cap(encoder.buffer) > retainedReportBytes || cap(decoder.buffer) > retainedReportBytes {
			t.Fatal("oversized idle buffers retained")
		}
		original := bytes.Clone(frame)
		for _, kind := range []string{"short", "magic", "truncated", "checksum", "too-small", "too-large"} {
			t.Run(kind, func(t *testing.T) {
				broken := bytes.Clone(original)
				switch kind {
				case "short":
					broken = broken[:7]
				case "magic":
					broken[0] ^= 1
				case "truncated":
					broken = broken[:len(broken)-1]
				case "checksum":
					broken[len(broken)-1] ^= 1
				case "too-small":
					binary.BigEndian.PutUint32(broken[4:8], 1)
				case "too-large":
					binary.BigEndian.PutUint32(broken[4:8], MaxFrameBytes+1)
				}
				if _, err := decoder.Read(bytes.NewReader(broken)); err == nil {
					t.Fatal("malformed expansion accepted")
				}
			})
		}
	}
}

func BenchmarkReportFrameRoundTrip(b *testing.B) {
	encoder, err := NewReportEncoder()
	if err != nil {
		b.Fatal(err)
	}
	defer encoder.Close()
	decoder, err := NewReportDecoder()
	if err != nil {
		b.Fatal(err)
	}
	defer decoder.Close()
	raw := bytes.Repeat([]byte(`{"user_id":10001,"ip":"8.8.8.8","connections":12},`), 10000)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		frame, err := encoder.Encode(raw)
		if err != nil {
			b.Fatal(err)
		}
		if _, err = decoder.Read(bytes.NewReader(frame)); err != nil {
			b.Fatal(err)
		}
	}
}
