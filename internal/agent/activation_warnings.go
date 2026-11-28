package agent

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"syscall"

	"github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
)

var (
	errActivationSuperseded            = errors.New("configuration superseded")
	errActivationCertificateSuperseded = errors.New("CERTIFICATE_SUPERSEDED")
)

type activationStage string

const (
	activationValidation  activationStage = "validation"
	activationPreparation activationStage = "preparation"
	activationRuntime     activationStage = "runtime"
	activationFirewall    activationStage = "firewall"
	activationAssets      activationStage = "assets"
	activationPersistence activationStage = "persistence"
	activationUpdate      activationStage = "update_confirmation"
)

// Preserve the existing wire error and errors.Is when attaching a safe stage.
type activationAttemptError struct {
	stage activationStage
	err   error
}

func (e activationAttemptError) Error() string { return e.err.Error() }
func (e activationAttemptError) Unwrap() error { return e.err }

type activationDiagnostic struct {
	stage activationStage
	code  string
}

func describeActivationFailure(err error) activationDiagnostic {
	d := activationDiagnostic{stage: "unknown", code: "activation_failed"}
	var attempt activationAttemptError
	if errors.As(err, &attempt) {
		d.stage = attempt.stage
	}
	switch {
	case errors.Is(err, xray.ErrReloadUnsupported):
		d.code = "live_reload_unsupported"
		switch {
		case strings.Contains(err.Error(), "a removed outbound may still be selected"):
			d.code = "removed_outbound_still_selectable"
		case strings.Contains(err.Error(), "a previously routed outbound may still be selected"):
			d.code = "removed_outbound_previously_routed"
		}
	case errors.Is(err, context.DeadlineExceeded):
		d.code = "deadline_exceeded"
	case errors.Is(err, syscall.EADDRINUSE):
		d.code = "address_in_use"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		d.code = "address_not_available"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		d.code = "permission_denied"
	case errors.Is(err, syscall.ENOSPC):
		d.code = "no_space_left"
	}
	return d
}

// Activation can replay indefinitely. Use only finite, fixed stage/cause codes
// for persistent warnings, never native error text or configuration values.
type activationFailureLog struct {
	seen map[activationDiagnostic]struct{}
}

func (l *activationFailureLog) reset() { l.seen = nil }

func (l *activationFailureLog) warn(logger *slog.Logger, revision uint64, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, errActivationSuperseded) ||
		errors.Is(err, errActivationCertificateSuperseded) {
		return
	}
	d := describeActivationFailure(err)
	if _, ok := l.seen[d]; ok {
		return
	}
	if l.seen == nil {
		l.seen = make(map[activationDiagnostic]struct{})
	}
	l.seen[d] = struct{}{}
	logger.Warn("configuration activation failed", "revision", revision, "stage", string(d.stage), "code", d.code)
}
