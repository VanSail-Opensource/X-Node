// Package hourly enforces account-wide admitted-payload grants and byte credits.
package hourly

import (
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

type OwnerKey struct {
	ID         string
	Generation uint64
}

type Scope struct {
	Owner  OwnerKey
	DayUTC string
}

type BindingKey struct {
	Owner        OwnerKey
	EnrollmentID string
	PeriodID     string
	PrincipalID  int
}

type Authorization struct {
	Key         BindingKey
	PaidThrough time.Time
}

type Direction uint8

const (
	Upload Direction = iota
	Download
)

// Completion describes native delivery/draining, not a second quota decision.
// Successful Begin is final quota consumption regardless of delivery outcome.
type Outcome uint8

const (
	Accepted Outcome = iota
	NotHandedOff
	Uncertain
)

type Wait struct {
	Changed <-chan struct{}
	After   time.Duration
}

type Stopper interface{ Stop() bool }

type Options struct {
	Now        func() time.Time
	AfterFunc  func(time.Duration, func()) Stopper
	Nonce      func() string
	MaxOwners  int
	MaxFlows   int
	MaxPermits int
}

// Only the durable store creates installation tokens. Replays retain the same
// marker; callers cannot fabricate or alter an installed obligation.
type InstalledCredit struct {
	install protocol.HourlyCreditInstall
	digest  string
	marker  *creditInstallMarker
}

// Only an admission freeze can create an unused-credit proof candidate.
type SealCandidate struct {
	credit   InstalledCredit
	admitted [2]uint64
	unused   uint64
}
