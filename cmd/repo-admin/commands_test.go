package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDispatchReleaseUsesMainAndExactDecimalRunID(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	if err := api.protectRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := execute(context.Background(), api, "dispatch-release", options{version: "v2.0.20", runID: 9223372036854775807}, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"ref": "main", "inputs": map[string]any{"version": "v2.0.20", "quality_run_id": "9223372036854775807"}}
	if !reflect.DeepEqual(fixture.snapshot().dispatch, want) || fixture.writeCount("POST", "/actions/workflows/release.yml/dispatches") != 1 {
		t.Fatal("dispatch lost its canonical ref, inputs or integer precision")
	}
}

func TestDispatchRejectsInvalidInputsAndUnprotectedRepository(t *testing.T) {
	for _, opts := range []options{
		{version: "v02.0.20", runID: 1}, {version: "v2.0.20-rc1", runID: 1},
		{version: "v2.0.20", runID: 0}, {version: "v2.0.20", runID: -1},
		{version: "v2.0.20", runID: 1}, // Valid input still requires observed protection.
	} {
		api, fixture := newPolicyFixture(t)
		if err := execute(context.Background(), api, "dispatch-release", opts, io.Discard); err == nil {
			t.Fatal("unsafe dispatch accepted")
		}
		if len(fixture.snapshot().writes) != 0 {
			t.Fatal("rejected dispatch mutated repository settings")
		}
	}
}

func TestSigningRotationCannotResetPolicy(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	if err := api.protectRelease(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.writes = nil
	fixture.mu.Unlock()
	keyPath := filepath.Join(t.TempDir(), "fixture.key")
	if err := os.WriteFile(keyPath, []byte("fixture-signing-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := execute(context.Background(), api, "signing-secret", options{keyFile: keyPath}, io.Discard); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /environments/release/secrets/RELEASE_MINISIGN_SECRET_KEY", "DELETE /actions/secrets/RELEASE_MINISIGN_SECRET_KEY"}
	if !reflect.DeepEqual(fixture.snapshot().writes, want) {
		t.Fatal("key rotation mutated protection policy")
	}
	body := fixture.snapshot().secretBody
	if body["key_id"] != "fixture-public-key" || body["encrypted_value"] == "" || strings.Contains(string(mustJSON(body)), "fixture-signing-key") {
		t.Fatal("signing key was not sealed for the environment")
	}
}

func TestSigningRejectsUnprotectedRepositoryBeforeAnySecretRequest(t *testing.T) {
	api, fixture := newPolicyFixture(t)
	err := execute(context.Background(), api, "signing-secret", options{keyFile: "fixture-not-read-before-policy"}, io.Discard)
	if snapshot := fixture.snapshot(); err == nil || len(snapshot.writes) != 0 || snapshot.secretBody != nil {
		t.Fatal("key upload proceeded without release protection")
	}
}
