package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"syscall"
	"testing"

	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	"github.com/VanSail-Opensource/X-Node/internal/nlog"
	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/transport"
)

func TestActivationWarningsKeepOnlyFixedStagesAndCauses(t *testing.T) {
	var console bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&console, nil))
	const first, second = "first-unknown-credential", "second-unknown-credential"
	var warnings activationFailureLog
	record := func(revision uint64, stage activationStage, err error) {
		warnings.warn(logger, revision, activationAttemptError{stage: stage, err: err})
	}
	record(11, activationRuntime, fmt.Errorf("%w: a removed outbound may still be selected: %s", xray.ErrReloadUnsupported, first))
	record(12, activationPreparation, fmt.Errorf("invalid value %s", first))
	record(13, activationPreparation, fmt.Errorf("another invalid value %s", second))
	record(14, activationRuntime, fmt.Errorf("activate: %w", context.Canceled))
	record(15, activationPersistence, errActivationSuperseded)
	record(16, activationRuntime, errActivationCertificateSuperseded)
	record(17, activationRuntime, fmt.Errorf("listen address includes %s: %w", second, syscall.EADDRINUSE))
	record(18, activationPreparation, context.DeadlineExceeded)
	got := console.String()
	if strings.Contains(got, first) || strings.Contains(got, second) {
		t.Fatal("activation warning exposed an unregistered configuration value")
	}
	for _, fragment := range []string{
		"revision=11 stage=runtime code=removed_outbound_still_selectable",
		"revision=12 stage=preparation code=activation_failed",
		"revision=17 stage=runtime code=address_in_use",
		"revision=18 stage=preparation code=deadline_exceeded",
	} {
		if !strings.Contains(got, fragment) {
			t.Errorf("activation warning missing %q", fragment)
		}
	}
	if count := strings.Count(got, "configuration activation failed"); count != 4 {
		t.Fatalf("activation warning count = %d, want 4", count)
	}

	warnings.reset()
	record(19, activationPreparation, errors.New(first))
	if !strings.Contains(console.String(), "revision=19") {
		t.Fatal("successful activation did not reset warning deduplication")
	}
}

func TestActivationErrorPreservesWireDetailAndKind(t *testing.T) {
	inner := fmt.Errorf("listen failed: %w", syscall.EADDRINUSE)
	err := activationAttemptError{stage: activationRuntime, err: inner}
	if err.Error() != inner.Error() || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("stage wrapper changed the activation error")
	}
}

func TestNativeRealityRedactionForPendingAndAcceptedConfiguration(t *testing.T) {
	a := &Agent{Logs: nlog.NewStream(io.Discard), Client: &transport.Client{Token: "control-example"}}
	pending := protocol.Config{Xray: json.RawMessage(`{"outbounds":[{"streamSettings":{"realitySettings":{"ShortId":"pending-short-id","Mldsa65Verify":"pending-verify"}}}]}`)}
	accepted := protocol.Config{Xray: json.RawMessage(`{"inbounds":[{"streamSettings":{"realitySettings":{"shortIds":["","accepted-id-a","accepted-id-b"],"mldsa65Seed":"accepted-private-seed"}}}]}`)}
	a.registerSecrets(pending, accepted)
	for _, secret := range []string{"pending-short-id", "pending-verify", "accepted-id-a", "accepted-id-b", "accepted-private-seed"} {
		if strings.Contains(a.Logs.Redact("native rejected "+secret), secret) {
			t.Fatal("native activation error redaction missed a REALITY configuration value")
		}
	}
}
