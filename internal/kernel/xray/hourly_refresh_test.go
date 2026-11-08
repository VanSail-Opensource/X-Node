package xray

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
)

type hourlyPacketSink func(buf.MultiBuffer) error

func (f hourlyPacketSink) WriteMultiBuffer(mb buf.MultiBuffer) error { return f(mb) }

func TestHourlyGrantRefreshBeforeBeginRetainsExactDatagram(t *testing.T) {
	for _, direction := range []hourly.Direction{hourly.Upload, hourly.Download} {
		t.Run(map[hourly.Direction]string{hourly.Upload: "upload", hourly.Download: "download"}[direction], func(t *testing.T) {
			var nanos atomic.Int64
			base := time.Now().UTC()
			nanos.Store(base.UnixNano())
			controller := hourly.NewController(hourly.Options{Now: func() time.Time { return time.Unix(0, nanos.Load()).UTC() }})
			defer controller.SetSession("")
			key := hourly.BindingKey{Owner: hourly.OwnerKey{ID: "owner", Generation: 1}, EnrollmentID: "enrollment", PeriodID: "period", PrincipalID: 1}
			controller.SetSession(nativeHourlySession)
			if !controller.ApplyAuthorization(1, 1, []hourly.Authorization{{Key: key, PaidThrough: base.Add(time.Hour)}}) {
				t.Fatal("authorization rejected")
			}
			flow, err := controller.OpenFlow(key, func() {})
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			_, _, _ = flow.TryAcquire(direction, 7, 7)
			demand := controller.PendingDemand(1)[0]
			grant := protocol.HourlyGrant{SessionID: nativeHourlySession, Owner: demand.Owner, Nonce: demand.Nonce, Sequence: 1, DayUTC: base.Format(time.DateOnly), LifetimeMillis: 10000, RateBytesPerSecond: 1_000_000, BurstBytes: 16384}
			if _, err = controller.ApplyGrant(grant); err != nil {
				t.Fatal(err)
			}
			nanos.Add(int64(time.Millisecond))
			acquire, calls := hourlyAcquirer(flow), 0
			interleaved := func(ctx context.Context, d hourly.Direction, want, minimum int) (hourlyHandoff, error) {
				permit, err := acquire(ctx, d, want, minimum)
				calls++
				if err == nil && calls == 1 {
					grant.Sequence++
					grant.Nonce = controller.PendingDemand(1)[0].Nonce
					if _, err = controller.ApplyGrant(grant); err != nil {
						t.Fatal(err)
					}
				}
				return permit, err
			}
			packet := nativeHourlyBuffer("payload")
			destination := xnet.UDPDestination(xnet.LocalHostIP, 53)
			packet.UDP = &destination
			if direction == hourly.Upload {
				source := &nativeHourlySource{mb: buf.MultiBuffer{packet}, err: io.EOF}
				reader := &hourlyReader{Reader: source, ctx: context.Background(), acquire: interleaved, datagram: true}
				mb, err := reader.ReadMultiBuffer()
				defer buf.ReleaseMulti(mb)
				if !errors.Is(err, io.EOF) || len(mb) != 1 || mb[0] != packet || mb[0].UDP != &destination || string(mb[0].Bytes()) != "payload" || source.reads != 1 {
					t.Fatal("refresh lost or changed an unadmitted UDP buffer", err)
				}
			} else {
				writes := 0
				sink := hourlyPacketSink(func(mb buf.MultiBuffer) error {
					defer buf.ReleaseMulti(mb)
					writes++
					if len(mb) != 1 || mb[0] != packet || mb[0].UDP != &destination || string(mb[0].Bytes()) != "payload" {
						t.Fatal("refresh changed native writer ownership or UDP metadata")
					}
					return nil
				})
				writer := &hourlyWriter{Writer: sink, ctx: context.Background(), acquire: interleaved, datagram: true}
				if err = writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil || writes != 1 {
					t.Fatal("refresh lost or duplicated a UDP handoff", err)
				}
			}
			samples := controller.Samples()
			if calls != 2 || len(samples) != 1 || direction == hourly.Upload && (samples[0].UploadBytes != 7 || samples[0].DownloadBytes != 0) || direction == hourly.Download && (samples[0].UploadBytes != 0 || samples[0].DownloadBytes != 7) {
				t.Fatal("refresh fabricated or duplicated admitted bytes", calls, samples)
			}
		})
	}
}
