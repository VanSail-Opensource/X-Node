package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// IssueSequence is globally monotonic for one persistent agent identity.
type HourlyCreditInstall struct {
	ReservationID string      `json:"reservation_id"`
	IssueSequence uint64      `json:"issue_sequence,string"`
	Owner         HourlyOwner `json:"owner"`
	DayUTC        string      `json:"day_utc"`
	AgentID       string      `json:"agent_id"`
	BootID        string      `json:"boot_id"`
	SessionID     string      `json:"session_id"`
	ByteCeiling   uint64      `json:"byte_ceiling,string"`
	Kind          string      `json:"kind"`
}

type HourlyCreditProgress struct {
	ReservationID         string `json:"reservation_id"`
	IssueSequence         uint64 `json:"issue_sequence,string"`
	AdmittedUploadBytes   uint64 `json:"admitted_upload_bytes,string"`
	AdmittedDownloadBytes uint64 `json:"admitted_download_bytes,string"`
}

// A final immutable proof partitions the original obligation. Recovery preserves
// unknown residual; it never fabricates usage or unused credit after a crash.
type HourlyCreditProof struct {
	Install               HourlyCreditInstall `json:"install"`
	AdmittedUploadBytes   uint64              `json:"admitted_upload_bytes,string"`
	AdmittedDownloadBytes uint64              `json:"admitted_download_bytes,string"`
	UnusedBytes           uint64              `json:"unused_bytes,string"`
	UnknownBytes          uint64              `json:"unknown_bytes,string"`
	Recovery              bool                `json:"recovery"`
	Digest                string              `json:"digest"`
}

type HourlyCreditProofBatch struct {
	Proofs []HourlyCreditProof `json:"proofs"`
}

type HourlyCreditSeal struct {
	ReservationID string               `json:"reservation_id"`
	Expected      *HourlyCreditInstall `json:"expected,omitempty"`
}

type HourlyCreditAck struct {
	ReservationID string `json:"reservation_id"`
	IssueSequence uint64 `json:"issue_sequence,string"`
	Digest        string `json:"digest"`
}

func HourlyInstallDigest(install HourlyCreditInstall) string {
	b, _ := json.Marshal(install)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func HourlyProofDigest(proof HourlyCreditProof) string {
	proof.Digest = ""
	b, _ := json.Marshal(proof)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
