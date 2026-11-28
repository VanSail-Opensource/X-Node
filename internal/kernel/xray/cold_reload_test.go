package xray

import (
	"context"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func startColdReloadTestRuntime(t *testing.T, cfg protocol.Config) *Runtime {
	t.Helper()
	registry := sessions.New()
	registry.SetUsers(cfg.Users)
	runtime := New(registry)
	t.Cleanup(runtime.Stop)
	if err := runtime.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestColdReloadAppliesUnmarkedRoutedOutboundRemoval(t *testing.T) {
	const relayUUID = "550e8400-e29b-41d4-a716-446655440041"
	relay := memberRouteTestRelay(t, "old!", relayUUID)
	echo := echoListener(t)
	base, port := testConfig(t)
	old := memberRouteTestConfig(t, base, testMemberRoute{
		tag: "administrator-outbound", relayPort: relay, targetPort: echo.Addr().(*net.TCPAddr).Port,
		uuid: relayUUID,
	})
	old.MemberOutbounds = nil
	runtime := startColdReloadTestRuntime(t, old)
	instance := runtime.instance
	stream := dialInboundEcho(t, port, testUUID, echo)
	checkResponse(t, stream, "old!")

	next, err := runtime.Prepare(base)
	if err != nil {
		t.Fatal(err)
	}
	if blocker := outboundReloadBlocker(runtime.current, next); blocker == "" {
		t.Fatal("fixture does not require cold activation")
	}
	if err := runtime.ApplyPreparedContext(t.Context(), t.Context(), next, false); err != nil {
		t.Fatal(err)
	}
	stats := runtime.Statistics()
	if !runtime.Ready() || runtime.instance == instance || stats.Rebuilds != 2 || stats.LastMode != "cold_reload" {
		t.Fatalf("unsupported but valid routing change did not cold reload exactly once: %+v", stats)
	}
	checkReceiverStreamEnded(t, stream)
	fresh := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, fresh)
	instance = runtime.instance
	if err := runtime.Apply(t.Context(), base); err != nil || runtime.instance != instance ||
		runtime.Statistics().Rebuilds != 2 || runtime.Statistics().LastMode != "live" {
		t.Fatalf("identical revision unnecessarily cold reloaded: %v", err)
	}
	checkEcho(t, fresh)
}

func coldReloadStartupChange(t *testing.T, cfg protocol.Config) protocol.Config {
	t.Helper()
	return editNative(t, cfg, func(root map[string]any) {
		root["api"] = map[string]any{"tag": "admin-api", "services": []string{"StatsService"}}
	})
}

func TestColdReloadAppliesStartupOnlyChange(t *testing.T) {
	base, port := testConfig(t)
	runtime := startColdReloadTestRuntime(t, base)
	instance := runtime.instance
	echo := echoListener(t)
	before := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, before)

	next := coldReloadStartupChange(t, base)
	prepared, err := runtime.Prepare(next)
	if err != nil {
		t.Fatal(err)
	}
	if sameNonReloadableStatic(runtime.current, prepared) || receiverChanged(runtime.current, prepared) {
		t.Fatal("fixture is not a startup-only change")
	}
	if err := runtime.Apply(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	stats := runtime.Statistics()
	if !runtime.Ready() || runtime.instance == instance || stats.Rebuilds != 2 || stats.LastMode != "cold_reload" {
		t.Fatalf("startup-only change was not activated: %+v", stats)
	}
	checkReceiverStreamEnded(t, before)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
}

func TestColdReloadRejectsInvalidCancelledAndOccupiedCandidatesBeforeCutover(t *testing.T) {
	const extraTag = "extra"
	base, port := testConfig(t)
	runtime := startColdReloadTestRuntime(t, base)
	instance := runtime.instance
	echo := echoListener(t)
	stream := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, stream)
	checkUnchanged := func() {
		t.Helper()
		if !runtime.Ready() || runtime.instance != instance || runtime.Statistics().Rebuilds != 1 {
			t.Fatalf("failed preflight changed the working runtime: %+v", runtime.Statistics())
		}
		checkEcho(t, stream)
	}

	invalid := base
	invalid.Xray = []byte(`{"inbounds":false}`)
	if err := runtime.Apply(t.Context(), invalid); err == nil {
		t.Fatal("invalid configuration was accepted")
	}
	checkUnchanged()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	prepared, err := runtime.Prepare(coldReloadStartupChange(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.ApplyPreparedContext(t.Context(), ctx, prepared, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled change was not abandoned: %v", err)
	}
	checkUnchanged()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	extraPort := occupied.Addr().(*net.TCPAddr).Port
	updated := editNative(t, coldReloadStartupChange(t, base), func(root map[string]any) {
		in := root["inbounds"].([]any)
		extra := maps.Clone(in[0].(map[string]any))
		extra["tag"], extra["port"] = extraTag, extraPort
		root["inbounds"] = append(in, extra)
	})
	updated = protocol.Clone(updated)
	updated.Users[0].InboundTags = append(updated.Users[0].InboundTags, extraTag)
	if err := runtime.Apply(t.Context(), updated); err == nil {
		t.Fatal("occupied listener was accepted")
	}
	checkUnchanged()
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.registry.SetUsers(updated.Users)
	if err := runtime.Apply(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	if !runtime.Ready() || runtime.instance == instance || runtime.Statistics().LastMode != "cold_reload" {
		t.Fatal("corrected configuration was not activated")
	}
	checkReceiverStreamEnded(t, stream)
	checkEcho(t, dialInboundEcho(t, extraPort, testUUID, echo))
}

func TestColdReloadStartupFailureRestoresServingRuntimeAndSuppressesRepeat(t *testing.T) {
	base, port := testConfig(t)
	runtime := startColdReloadTestRuntime(t, base)
	instance := runtime.instance
	echo := echoListener(t)
	old := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, old)

	dir := t.TempDir()
	notDir := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(notDir, []byte("test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	withLogPath := func(path string) protocol.Config {
		t.Helper()
		return editNative(t, base, func(root map[string]any) {
			root["log"] = map[string]any{"loglevel": "warning", "access": "none", "error": path}
		})
	}
	bad := withLogPath(filepath.Join(notDir, "native.log"))
	prepareAndApply := func(cfg protocol.Config) error {
		t.Helper()
		candidate, err := runtime.Prepare(cfg)
		if err != nil {
			t.Fatalf("fixture should compile before startup: %v", err)
		}
		return runtime.ApplyPreparedContext(t.Context(), t.Context(), candidate, false)
	}
	if err := prepareAndApply(bad); err == nil || !strings.Contains(err.Error(), "previous runtime restored") {
		t.Fatalf("failed cutover did not restore the previous runtime: %v", err)
	}
	stats := runtime.Statistics()
	if !runtime.Ready() || runtime.instance == instance || stats.Rebuilds != 2 || stats.LastMode != "cold_rollback" {
		t.Fatalf("rollback did not recover the previous listener: %+v", stats)
	}
	checkReceiverStreamEnded(t, old)
	recoveredInstance := runtime.instance
	recovered := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, recovered)

	if err := prepareAndApply(base); err != nil || runtime.instance != recoveredInstance {
		t.Fatalf("reapplying the accepted configuration should stay live: %v", err)
	}
	// A different account snapshot cannot fix a native startup failure.
	bad.Users = append(bad.Users, protocol.User{ID: 42, UUID: additionalInboundUser, InboundTags: []string{"in"}})
	if err := prepareAndApply(bad); err == nil || !strings.Contains(err.Error(), "already failed") {
		t.Fatalf("unchanged failed native candidate was retried after account churn: %v", err)
	}
	if runtime.instance != recoveredInstance || runtime.Statistics().Rebuilds != 2 {
		t.Fatal("automatic repeat interrupted the recovered instance")
	}
	checkEcho(t, recovered)

	if err := prepareAndApply(withLogPath(filepath.Join(dir, "native.log"))); err != nil {
		t.Fatalf("corrected native candidate was not allowed to retry: %v", err)
	}
	if !runtime.Ready() || runtime.instance == recoveredInstance || runtime.Statistics().LastMode != "cold_reload" {
		t.Fatal("corrected configuration was not activated")
	}
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
}

func TestColdReloadGRPCListenerOwnershipAndReadiness(t *testing.T) {
	const grpcTag = "grpc-in"
	base, port := testConfig(t)
	runtime := startColdReloadTestRuntime(t, base)
	instance := runtime.instance
	echo := echoListener(t)
	old := dialInboundEcho(t, port, testUUID, echo)
	checkEcho(t, old)

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	grpcPort := occupied.Addr().(*net.TCPAddr).Port
	grpcStream := map[string]any{"network": "grpc", "grpcSettings": map[string]any{"serviceName": "carpool"}}
	updated := editNative(t, base, func(root map[string]any) {
		in := root["inbounds"].([]any)
		extra := maps.Clone(in[0].(map[string]any))
		extra["tag"], extra["port"], extra["streamSettings"] = grpcTag, grpcPort, grpcStream
		root["inbounds"] = append(in, extra)
	})
	updated = protocol.Clone(updated)
	updated.Users[0].InboundTags = append(updated.Users[0].InboundTags, grpcTag)
	if err := runtime.Apply(t.Context(), updated); err == nil || runtime.instance != instance || !runtime.Ready() {
		t.Fatalf("occupied gRPC receiver disturbed the old runtime: %v", err)
	}
	checkEcho(t, old)
	if err := occupied.Close(); err != nil {
		t.Fatal(err)
	}
	runtime.registry.SetUsers(updated.Users)
	if err := runtime.Apply(t.Context(), updated); err != nil {
		t.Fatal(err)
	}
	if !runtime.Ready() || runtime.instance == instance || runtime.Statistics().LastMode != "cold_reload" {
		t.Fatalf("fresh gRPC receiver was not activated: %+v", runtime.Statistics())
	}
	checkReceiverStreamEnded(t, old)
	checkEcho(t, dialInboundEcho(t, port, testUUID, echo))
	peer := memberRouteTestVLESS("peer", grpcPort, testUUID)
	peer["streamSettings"] = grpcStream
	client := nativeClient(t, peer)
	conn, err := core.Dial(t.Context(), client, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	checkEcho(t, conn)
}
