package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
)

const ReportFramingCapability = "report_zstd_l6_v1"
const ReportFramingHeader = "X-XNode-Reports"
const ZstdReportFraming = "zstd-l6-v1"
const ReportZstdLevel = 6
const MaxReportFrameBytes = MaxFrameBytes + MaxFrameBytes/128 + 1024
const reportWindowBytes = 1 << 20
const retainedReportBytes = 512 << 10

var reportMagic = [4]byte{'X', 'N', 'Z', 1}
var ErrReportFrame = errors.New("invalid or oversized compressed report frame")

func IsReport(kind string) bool {
	switch kind {
	case "telemetry.report", "telemetry.compact", "traffic.report", "logs.report", "firewall.events", "ddns.changes":
		return true
	}
	return false
}

// ReportEncoder belongs to the serialized transport writer. One level-6 worker
// is reused across reports/reconnects; frames are independent and never use disk.
type ReportEncoder struct {
	codec  *zstd.Encoder
	buffer []byte
}

func NewReportEncoder() (*ReportEncoder, error) {
	codec, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(ReportZstdLevel)),
		zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(reportWindowBytes),
		zstd.WithLowerEncoderMem(true), zstd.WithEncoderCRC(true))
	if err != nil {
		return nil, err
	}
	return &ReportEncoder{codec: codec}, nil
}

// Encode returns borrowed storage valid until the next Encode. Large frames
// are released after the caller's write rather than retained on an idle client.
func (e *ReportEncoder) Encode(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > MaxFrameBytes {
		return nil, ErrReportFrame
	}
	frame := append(e.buffer[:0], reportMagic[:]...)
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(raw)))
	frame = e.codec.EncodeAll(raw, frame)
	e.buffer = retainReportBuffer(frame)
	if len(frame) > MaxReportFrameBytes {
		return nil, ErrReportFrame
	}
	return frame, nil
}

func (e *ReportEncoder) Close() error { return e.codec.Close() }

// ReportDecoder belongs to one socket reader, with bounded input, window and
// output allocation. The length prefix is enforced even for malicious zstd sizes.
type ReportDecoder struct {
	codec  *zstd.Decoder
	buffer []byte
}

func NewReportDecoder() (*ReportDecoder, error) {
	codec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true),
		zstd.WithDecoderMaxWindow(reportWindowBytes), zstd.WithDecoderMaxMemory(MaxFrameBytes), zstd.WithDecodeAllCapLimit(true))
	if err != nil {
		return nil, err
	}
	return &ReportDecoder{codec: codec}, nil
}

// Read returns borrowed decoded storage valid until the next Read. Parsing a
// Message copies its JSON data before the decoder buffer can be reused.
func (d *ReportDecoder) Read(reader io.Reader) ([]byte, error) {
	frame, err := io.ReadAll(io.LimitReader(reader, MaxReportFrameBytes+1))
	if err != nil {
		return nil, err
	}
	if len(frame) < 8 || len(frame) > MaxReportFrameBytes || !bytes.Equal(frame[:4], reportMagic[:]) {
		return nil, ErrReportFrame
	}
	size := int(binary.BigEndian.Uint32(frame[4:8]))
	if size == 0 || size > MaxFrameBytes {
		return nil, ErrReportFrame
	}
	buffer := d.buffer[:0]
	if cap(buffer) < size {
		buffer = make([]byte, 0, size)
	}
	raw, err := d.codec.DecodeAll(frame[8:], buffer[:0:size])
	d.buffer = retainReportBuffer(raw)
	if err != nil || len(raw) != size {
		return nil, ErrReportFrame
	}
	return raw, nil
}

func (d *ReportDecoder) Close() { d.codec.Close(); d.buffer = nil }
func retainReportBuffer(value []byte) []byte {
	if cap(value) > retainedReportBytes {
		return nil
	}
	return value[:0]
}
