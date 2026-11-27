package xray

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
)

func TestCustomRouteEditsDoNotReconfigureOtherUsers(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	cfg, port := testConfig(t)
	other := protocol.User{ID: 2, UUID: "550e8400-e29b-41d4-a716-446655440002", InboundTags: []string{"in"}}
	cfg.Users = append(cfg.Users, other)
	registry := sessions.New()
	registry.SetUsers(cfg.Users)
	runtime := New(registry)
	defer runtime.Stop()
	if err := runtime.Apply(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	instance, epoch := runtime.instance, runtime.current.Epochs["in"]
	client := nativeClient(t, map[string]any{"tag": "peer", "protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{
		"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": other.UUID, "encryption": "none"}},
	}}}})
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(echo.Addr().(*net.TCPAddr).Port))
	dial := func() net.Conn {
		t.Helper()
		conn, err := core.Dial(t.Context(), client, dest)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	check := func(conn net.Conn) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		var got [2]byte
		if _, err := io.ReadFull(conn, got[:]); err != nil || string(got[:]) != "ok" {
			t.Fatalf("unrelated user flow failed: %q (%v)", got, err)
		}
	}
	keep := dial()
	defer keep.Close()
	check(keep)
	good := editNative(t, cfg, func(root map[string]any) {
		root["routing"] = map[string]any{"rules": []any{map[string]any{
			"type": "field", "ruleTag": "member-one", "user": []string{protocol.UserEmail(cfg.Users[0], "in")},
			"domain": []string{"full:member.invalid"}, "outboundTag": "direct",
		}}}
	})
	if err := runtime.Apply(t.Context(), good); err != nil {
		t.Fatal(err)
	}
	active := runtime.current
	before := runtime.Statistics()
	invalid := editNative(t, good, func(root map[string]any) {
		route := root["routing"].(map[string]any)
		route["rules"] = append(route["rules"].([]any), map[string]any{"type": "field", "outboundTag": "direct"})
	})
	global := editNative(t, good, func(root map[string]any) {
		root["routing"].(map[string]any)["domainStrategy"] = "IPIfNonMatch"
	})
	for _, candidate := range []protocol.Config{invalid, global} {
		if err := runtime.Apply(t.Context(), candidate); err == nil {
			t.Fatal("invalid or disruptive routing change was published")
		}
		check(keep)
		fresh := dial()
		check(fresh)
		_ = fresh.Close()
	}
	after := runtime.Statistics()
	if runtime.current != active || runtime.instance != instance || runtime.current.Epochs["in"] != epoch ||
		after.Rebuilds != 1 || after.HandlerReplacements != before.HandlerReplacements || after.MatcherBuilds != before.MatcherBuilds || !runtime.Ready() {
		t.Fatalf("failed edits changed the serving configuration: before=%+v after=%+v", before, after)
	}
}

func TestRuleCompilationReusesUnchangedRulesInCandidateOrder(t *testing.T) {
	cfg, _ := testConfig(t)
	maker := func(order ...int) protocol.Config {
		return editNative(t, cfg, func(root map[string]any) {
			var rules []any
			for _, i := range order {
				rules = append(rules, map[string]any{"type": "field", "ruleTag": fmt.Sprint(i), "domain": []string{fmt.Sprintf("full:%d.example", i)}, "outboundTag": "direct"})
			}
			root["routing"] = map[string]any{"rules": rules}
		})
	}
	previous, err := Prepare(maker(1, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	next, err := PrepareCached(maker(3, 2, 4), previous)
	if err != nil {
		t.Fatal(err)
	}
	if next.Router.Rule[0] != previous.Router.Rule[2] || next.Router.Rule[1] != previous.Router.Rule[1] ||
		next.Router.Rule[2].RuleTag != "4" || previous.Router.Rule[0].RuleTag != "1" {
		t.Fatal("candidate changed order, rebuilt untouched rules, or mutated old state")
	}
}
