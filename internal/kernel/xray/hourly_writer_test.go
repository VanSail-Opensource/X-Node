package xray

import (
	"context"
	"errors"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/xtls/xray-core/common/buf"
)

type nativeHourlySink struct {
	payload string
	lengths []int
	held    buf.MultiBuffer
	err     error
}

func (s *nativeHourlySink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if s.err != nil {
		s.held = mb // Ownership remains here, including when Write returns an error.
		return s.err
	}
	s.lengths = append(s.lengths, int(mb.Len()))
	for _, b := range mb {
		s.payload += string(b.Bytes())
	}
	buf.ReleaseMulti(mb)
	return nil
}

func TestHourlyWriterHandsOffExactlyAdmittedSlices(t *testing.T) {
	sink := &nativeHourlySink{}
	admitted := 0
	var outcomes []hourly.Outcome
	w := &hourlyWriter{Writer: sink, ctx: context.Background(), acquire: nativeHourlyAcquirer(3, &admitted, &outcomes)}
	if err := w.WriteMultiBuffer(buf.MultiBuffer{nativeHourlyBuffer("abcde"), nativeHourlyBuffer("fghi")}); err != nil {
		t.Fatal(err)
	}
	if sink.payload != "abcdefghi" || admitted != 9 || len(sink.lengths) != 4 {
		t.Fatal("writer dropped bytes or charged bytes beyond the native handoff")
	}
	for _, n := range sink.lengths {
		if n > 3 {
			t.Fatal("handoff exceeded permit")
		}
	}
}

func TestHourlyWriterErrorRetainsChargeAndDoesNotReleaseHandedBuffer(t *testing.T) {
	writeErr := errors.New("delivery uncertain")
	sink := &nativeHourlySink{err: writeErr}
	admitted := 0
	var outcomes []hourly.Outcome
	w := &hourlyWriter{Writer: sink, ctx: context.Background(), acquire: nativeHourlyAcquirer(3, &admitted, &outcomes)}
	head, tail := nativeHourlyBuffer("abc"), nativeHourlyBuffer("tail")
	defer func() { buf.ReleaseMulti(sink.held) }()
	if err := w.WriteMultiBuffer(buf.MultiBuffer{head, tail}); !errors.Is(err, writeErr) {
		t.Fatal("writer hid underlying failure")
	}
	if admitted != 3 || len(outcomes) != 1 || outcomes[0] != hourly.Uncertain || head.Len() != 3 || tail.Len() != 0 {
		t.Fatal("failed write refunded admitted quota, double-released handed data, or retained tail")
	}
}

func TestHourlyWriterFailedBeginNeverHandsOff(t *testing.T) {
	sink := &nativeHourlySink{}
	admitted := 0
	var outcomes []hourly.Outcome
	w := &hourlyWriter{Writer: sink, ctx: context.Background(), acquire: func(context.Context, hourly.Direction, int, int) (hourlyHandoff, error) {
		return &nativeHourlyPermit{n: 2, beginErr: hourly.ErrRevoked, admitted: &admitted, outcomes: &outcomes}, nil
	}}
	head := nativeHourlyBuffer("abcd")
	if err := w.WriteMultiBuffer(buf.MultiBuffer{head}); !errors.Is(err, hourly.ErrRevoked) {
		t.Fatal("revoked Begin accepted")
	}
	if admitted != 0 || sink.payload != "" || head.Len() != 0 || len(outcomes) != 1 || outcomes[0] != hourly.NotHandedOff {
		t.Fatal("unstarted handoff reached native writer or leaked buffers")
	}
}

func TestHourlyWriterCancellationBetweenReserveAndBeginReleasesOnlyReservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sink := &nativeHourlySink{}
	admitted := 0
	var outcomes []hourly.Outcome
	w := &hourlyWriter{Writer: sink, ctx: ctx, acquire: func(context.Context, hourly.Direction, int, int) (hourlyHandoff, error) {
		cancel()
		return &nativeHourlyPermit{n: 2, admitted: &admitted, outcomes: &outcomes}, nil
	}}
	data := nativeHourlyBuffer("abcd")
	if err := w.WriteMultiBuffer(buf.MultiBuffer{data}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was ignored before admission")
	}
	if admitted != 0 || sink.payload != "" || data.Len() != 0 || len(outcomes) != 1 || outcomes[0] != hourly.NotHandedOff {
		t.Fatal("canceled reservation consumed payload or quota")
	}
}
