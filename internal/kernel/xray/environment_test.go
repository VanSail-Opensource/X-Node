package xray

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func TestNativeRuntimeEnvironmentRestoresOmittedKeysAndRollsBack(t *testing.T) {
	const ambient, missing = "XN_TEST_AMBIENT", "XN_TEST_MISSING"
	t.Setenv(ambient, "") // An empty ambient value is distinct from an unset key.
	t.Setenv(missing, "")
	if err := os.Unsetenv(missing); err != nil {
		t.Fatal(err)
	}
	nativeEnvironmentMu.Lock()
	defer nativeEnvironmentMu.Unlock()
	prior := nativeRuntimeBaseline
	nativeRuntimeBaseline = nil
	defer func() { nativeRuntimeBaseline = prior }()

	expect := func(key, want string, exists bool) {
		t.Helper()
		got, present := os.LookupEnv(key)
		if got != want || present != exists {
			t.Fatalf("%s = (%q, %t), want (%q, %t)", key, got, present, want, exists)
		}
	}
	start := func(values map[string]string) (func(), func()) {
		t.Helper()
		restore, commit, err := beginNativeRuntimeEnvironment(values)
		if err != nil {
			t.Fatal(err)
		}
		return restore, commit
	}
	_, commit := start(map[string]string{ambient: "live", missing: "live"})
	commit()
	expect(ambient, "live", true)
	expect(missing, "live", true)

	restore, _ := start(nil)
	expect(ambient, "", true)
	expect(missing, "", false)
	restore()
	restore() // Recovery may restore before the outer error defer does.
	expect(ambient, "live", true)
	expect(missing, "live", true)

	if _, _, err := beginNativeRuntimeEnvironment(map[string]string{"invalid=key": "value"}); err == nil {
		t.Fatal("staging accepted an invalid process environment key")
	}
	expect(ambient, "live", true)
	expect(missing, "live", true)

	_, commit = start(nil)
	commit()
	expect(ambient, "", true)
	expect(missing, "", false)
	if len(nativeRuntimeBaseline) != 0 {
		t.Fatal("committing removal retained inactive process environment keys")
	}
}

func TestRemovedNativeEnvironmentRecompilesEnvBackedListener(t *testing.T) {
	const key = "XRAY_RAY_BUFFER_SIZE"
	t.Setenv(key, "31337")
	t.Setenv("xray.ray.buffer.size", "")
	if err := os.Unsetenv("xray.ray.buffer.size"); err != nil {
		t.Fatal(err)
	}
	base, _ := testConfig(t)
	base = editNative(t, base, func(root map[string]any) {
		root["inbounds"].([]any)[0].(map[string]any)["port"] = "env:" + key
	})
	managed := editNative(t, base, func(root map[string]any) {
		root["env"] = map[string]any{key: "31338"}
	})
	old, err := Prepare(managed)
	if err != nil {
		t.Fatal(err)
	}
	expectPort := func(got *Prepared, want uint32) {
		t.Helper()
		receiver, err := receiverSettings(got.Inbounds["in"])
		if err != nil {
			t.Fatal(err)
		}
		ranges := receiver.GetPortList().GetRange()
		if len(ranges) != 1 || ranges[0].From != want || ranges[0].To != want {
			t.Fatalf("resolved requests did not use port %d", want)
		}
	}
	expectPort(old, 31338)
	if got := os.Getenv(key); got != "31337" {
		t.Fatal("preparation exposed the candidate override to the process")
	}
	nativeEnvironmentMu.Lock()
	prior := nativeRuntimeBaseline
	nativeRuntimeBaseline = nil
	_, commit, err := beginNativeRuntimeEnvironment(preparedEnvironment(old))
	if err == nil {
		commit()
	}
	nativeEnvironmentMu.Unlock()
	t.Cleanup(func() {
		nativeEnvironmentMu.Lock()
		nativeRuntimeBaseline = prior
		nativeEnvironmentMu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}

	next, err := PrepareCached(base, old)
	if err != nil {
		t.Fatal(err)
	}
	expectPort(next, 31337)
	if got := os.Getenv(key); got != "31338" {
		t.Fatal("prepared replacement changed the serving environment")
	}
}

func TestRejectedEnvironmentCannotChangeProcessBeforeNativeValidation(t *testing.T) {
	t.Setenv("XRAY_BUF_READV", "original")
	before, present := os.LookupEnv("LD_PRELOAD")
	c := protocol.Config{Xray: json.RawMessage(`{"env":{"XRAY_BUF_READV":"true","LD_PRELOAD":"/untrusted"},"inbounds":[]}`)}
	if _, err := Prepare(c); err == nil {
		t.Fatal("native validator accepted unsafe environment")
	}
	if os.Getenv("XRAY_BUF_READV") != "original" {
		t.Fatal("partial environment was applied before rejection")
	}
	if after, exists := os.LookupEnv("LD_PRELOAD"); after != before || exists != present {
		t.Fatal("loader environment changed")
	}
}
