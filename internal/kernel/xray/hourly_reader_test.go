package xray

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

func TestHourlyReaderExactSlicesAndDeferredEOF(t *testing.T) {
	source := &nativeHourlySource{mb: buf.MultiBuffer{nativeHourlyBuffer("abcde"), nativeHourlyBuffer("fghi")}, err: io.EOF}
	admitted := 0
	var outcomes []hourly.Outcome
	r := &hourlyReader{Reader: source, ctx: context.Background(), acquire: nativeHourlyAcquirer(2, &admitted, &outcomes)}
	var payload string
	for _, expected := range []string{"ab", "cd", "e", "fg", "hi"} {
		mb, err := r.ReadMultiBuffer()
		last := expected == "hi"
		if len(mb) != 1 || string(mb[0].Bytes()) != expected || last && !errors.Is(err, io.EOF) || !last && err != nil {
			t.Fatalf("slice %q returned length=%d error=%v", expected, mb.Len(), err)
		}
		payload += string(mb[0].Bytes())
		buf.ReleaseMulti(mb)
	}
	if payload != "abcdefghi" || admitted != 9 || source.reads != 1 || len(outcomes) != 5 {
		t.Fatal("stream slicing lost bytes, charged a tail, or read past EOF")
	}
}

func TestHourlyReaderKeepsUDPMetadataAndEmptyPackets(t *testing.T) {
	for _, payload := range []string{"", "packet"} {
		t.Run(payload, func(t *testing.T) {
			packet := nativeHourlyBuffer(payload)
			destination := xnet.UDPDestination(xnet.LocalHostIP, 53)
			packet.UDP = &destination
			source := &nativeHourlySource{mb: buf.MultiBuffer{packet}, err: io.EOF}
			admitted, minimum := 0, -1
			var outcomes []hourly.Outcome
			acquire := nativeHourlyAcquirer(1, &admitted, &outcomes)
			r := &hourlyReader{Reader: source, ctx: context.Background(), acquire: func(ctx context.Context, d hourly.Direction, want, atomic int) (hourlyHandoff, error) {
				minimum = atomic
				return acquire(ctx, d, want, atomic)
			}}
			mb, err := r.ReadMultiBuffer()
			defer buf.ReleaseMulti(mb)
			if !errors.Is(err, io.EOF) || len(mb) != 1 || mb[0] != packet || mb[0].UDP != &destination || minimum != len(payload) || admitted != len(payload) {
				t.Fatal("datagram split, metadata lost, or empty packet discarded")
			}
		})
	}
}

func TestHourlyReaderRejectsOversizePacketBeforeAdmission(t *testing.T) {
	packet := nativeHourlyBuffer(strings.Repeat("x", 16385))
	r := &hourlyReader{Reader: &nativeHourlySource{mb: buf.MultiBuffer{packet}}, ctx: context.Background(), datagram: true, acquire: func(context.Context, hourly.Direction, int, int) (hourlyHandoff, error) {
		t.Fatal("oversize indivisible packet requested admission")
		return nil, nil
	}}
	if mb, err := r.ReadMultiBuffer(); len(mb) != 0 || !errors.Is(err, hourly.ErrInvalid) || packet.Len() != 0 {
		t.Fatal("oversize packet was retained or admitted")
	}
}

func TestHourlyReaderInterruptWakesWaitingAdmissionAndReleasesTail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	packet := nativeHourlyBuffer("waiting")
	r := &hourlyReader{Reader: &nativeHourlySource{mb: buf.MultiBuffer{packet}}, ctx: ctx, cancel: cancel, acquire: func(ctx context.Context, _ hourly.Direction, _, _ int) (hourlyHandoff, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	done := make(chan error, 1)
	go func() { _, err := r.ReadMultiBuffer(); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("admission not reached")
	}
	r.Interrupt()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || packet.Len() != 0 {
			t.Fatal("interrupt lost cancellation or buffered ownership")
		}
	case <-time.After(time.Second):
		t.Fatal("interrupt failed to wake admission")
	}
}
