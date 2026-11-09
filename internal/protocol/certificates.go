package protocol

import (
	"errors"
	"time"
)

const CertificateLifecycleCapability = "certificate_lifecycle_v1"
const CertificateRunCommand = "certificates.run"
const MaxCertificateProfiles = 64

type CertificateRunArgs struct {
	ProfileID        string `json:"profile_id"`
	Action           string `json:"action"`
	ExpectedRevision uint64 `json:"expected_revision"`
}

func (a CertificateRunArgs) Validate() error {
	if !ValidName(a.ProfileID) || a.Action != "issue" && a.Action != "renew" || a.ExpectedRevision == 0 {
		return errors.New("CERTIFICATE_INPUT_INVALID")
	}
	return nil
}

type CertificateRunProgress struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Phase     string `json:"phase"`
}

type CertificateRunResult struct {
	ProfileID   string    `json:"profile_id"`
	Action      string    `json:"action"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Expires     time.Time `json:"expires,omitempty"`
	Applied     bool      `json:"applied"`
	Ready       bool      `json:"ready"`
}

// CertificateStatus contains public certificate facts only, never PEM or paths.
// Fingerprint/validity describe serving material; AcquiredFingerprint may differ.
type CertificateStatus struct {
	Domain              string    `json:"domain"`
	Mode                string    `json:"mode"`
	Phase               string    `json:"phase"`
	Active              bool      `json:"active"`
	Fingerprint         string    `json:"fingerprint,omitempty"`
	AcquiredFingerprint string    `json:"acquired_fingerprint,omitempty"`
	NotBefore           time.Time `json:"not_before,omitempty"`
	Expires             time.Time `json:"expires"`
	Expiring            bool      `json:"expiring"`
	SANs                []string  `json:"sans,omitempty"`
	Issuer              string    `json:"issuer,omitempty"`
	ObtainMillis        int64     `json:"obtain_millis"`
	CommandID           string    `json:"command_id,omitempty"`
	Revision            uint64    `json:"revision,string"`
	LastAttempt         time.Time `json:"last_attempt,omitempty"`
	LastSuccess         time.Time `json:"last_success,omitempty"`
	ErrorCode           string    `json:"error_code,omitempty"`
}
