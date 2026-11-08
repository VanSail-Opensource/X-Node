package xray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/hourly"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func nativeHourlyExchange(conn net.Conn) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("echo"))
		if err == nil {
			var reply [4]byte
			_, err = io.ReadFull(conn, reply[:])
			if err == nil && string(reply[:]) != "echo" {
				err = errors.New("hourly echo changed payload")
			}
		}
		done <- err
	}()
	return done
}

func grantNativeHourlyDemand(t *testing.T, c *hourly.Controller, session string, sequence uint64, lifetime uint32) protocol.HourlyGrant {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, demand := range c.PendingDemands() {
			if demand.PendingBytes == 0 {
				continue
			}
			grant := protocol.HourlyGrant{SessionID: session, Owner: demand.Owner, Nonce: demand.Nonce, Sequence: sequence, DayUTC: time.Now().UTC().Format(time.DateOnly), LifetimeMillis: lifetime, RateBytesPerSecond: 1_000_000, BurstBytes: 16384}
			if _, err := c.ApplyGrant(grant); err != nil {
				t.Fatal(err)
			}
			return grant
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("native flow did not demand missing control authority")
	return protocol.HourlyGrant{}
}

func TestRealHourlyIdleTCPAndMuxPauseAndResumeWithoutDisconnect(t *testing.T) {
	for _, mux := range []bool{false, true} {
		for _, mode := range []string{"grant-expiry", "session"} {
			t.Run(fmt.Sprintf("mux=%t/%s", mux, mode), func(t *testing.T) {
				echo := echoListener(t)
				cfg, port := testConfig(t)
				registry, controller := nativeHourlyRegistry(t, &cfg)
				runtime := New(registry)
				defer runtime.Stop()
				if err := runtime.Apply(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
				peer := map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": testUUID, "encryption": "none"}}}}}}
				if mux {
					peer["mux"] = map[string]any{"enabled": true, "concurrency": 8}
				}
				conn, err := core.Dial(context.Background(), nativeClient(t, peer), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				defer boundHourlyIO(t, conn)()
				first := nativeHourlyExchange(conn)
				lifetime := uint32(10000)
				if mode == "grant-expiry" {
					lifetime = 250
				}
				old := grantNativeHourlyDemand(t, controller, nativeHourlySession, 1, lifetime)
				if err = <-first; err != nil {
					t.Fatal(err)
				}
				awaitMeteredTraffic(t, registry, 1, 4, 4)
				if mode == "grant-expiry" {
					time.Sleep(300 * time.Millisecond)
				} else {
					controller.SetSession("")
				}
				second := nativeHourlyExchange(conn)
				select {
				case err = <-second:
					t.Fatal("missing authority disconnected or admitted payload", err)
				case <-time.After(25 * time.Millisecond):
				}
				assertNativeHourlySamples(t, controller, 4)
				if registry.Summary().TotalConnections[1] != 1 {
					t.Fatal("idle control retirement closed its logical native flow")
				}
				session := nativeHourlySession
				if mode == "session" {
					session = "22222222222222222222222222222222"
					controller.SetSession(session)
				}
				if _, err = controller.ApplyGrant(old); !errors.Is(err, hourly.ErrRevoked) {
					t.Fatal("old control authority was reusable", err)
				}
				fresh := grantNativeHourlyDemand(t, controller, session, 2, 10000)
				if fresh.Nonce == old.Nonce {
					t.Fatal("resumption reused an old demand nonce")
				}
				if err = <-second; err != nil {
					t.Fatal("fresh authority did not resume the same native connection", err)
				}
				awaitMeteredTraffic(t, registry, 1, 8, 8)
				assertNativeHourlySamples(t, controller, 8)
			})
		}
	}
}
