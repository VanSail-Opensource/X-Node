package protocol

import (
	"encoding/hex"
	"errors"
	"math"
)

func ValidateHourlyInstall(install HourlyCreditInstall) error {
	if !ValidName(install.ReservationID) || install.IssueSequence == 0 || install.IssueSequence > math.MaxInt64 || ValidateHourlyOwner(install.Owner) != nil || !ValidHourlyDay(install.DayUTC) || !ValidStreamID(install.AgentID) || !ValidStreamID(install.BootID) || !ValidStreamID(install.SessionID) || install.ByteCeiling == 0 || install.ByteCeiling > math.MaxInt64 || install.Kind != "free" && install.Kind != "extra" {
		return errors.New("invalid hourly credit installation")
	}
	return nil
}

func ValidateHourlyProgress(progress HourlyCreditProgress) error {
	if !ValidName(progress.ReservationID) || progress.IssueSequence == 0 || progress.IssueSequence > math.MaxInt64 || progress.AdmittedUploadBytes > math.MaxInt64 || progress.AdmittedDownloadBytes > math.MaxInt64-progress.AdmittedUploadBytes {
		return errors.New("invalid hourly admitted progress")
	}
	return nil
}

func ValidateHourlyProof(proof HourlyCreditProof) error {
	if ValidateHourlyInstall(proof.Install) != nil {
		return errors.New("invalid hourly proof binding")
	}
	remaining := proof.Install.ByteCeiling
	for _, bytes := range []uint64{proof.AdmittedUploadBytes, proof.AdmittedDownloadBytes, proof.UnusedBytes, proof.UnknownBytes} {
		if bytes > remaining {
			return errors.New("hourly proof exceeds its reservation")
		}
		remaining -= bytes
	}
	if remaining != 0 || proof.Recovery && proof.UnusedBytes != 0 || !proof.Recovery && proof.UnknownBytes != 0 || proof.Digest != HourlyProofDigest(proof) {
		return errors.New("incomplete or inconsistent hourly proof")
	}
	return nil
}

func ValidateHourlyAck(ack HourlyCreditAck) error {
	decoded, err := hex.DecodeString(ack.Digest)
	if !ValidName(ack.ReservationID) || ack.IssueSequence == 0 || ack.IssueSequence > math.MaxInt64 || err != nil || len(decoded) != 32 {
		return errors.New("invalid hourly proof acknowledgment")
	}
	return nil
}

func ValidateHourlySeal(seal HourlyCreditSeal) error {
	if !ValidName(seal.ReservationID) || seal.Expected != nil && (seal.Expected.ReservationID != seal.ReservationID || ValidateHourlyInstall(*seal.Expected) != nil) {
		return errors.New("invalid hourly credit seal binding")
	}
	return nil
}

func ValidateHourlyProofBatch(batch HourlyCreditProofBatch) error {
	if len(batch.Proofs) == 0 || len(batch.Proofs) > MaxHourlyItems {
		return errors.New("invalid hourly proof batch")
	}
	seen := map[string]bool{}
	for _, proof := range batch.Proofs {
		if ValidateHourlyProof(proof) != nil || seen[proof.Install.ReservationID] {
			return errors.New("invalid or duplicate hourly proof")
		}
		seen[proof.Install.ReservationID] = true
	}
	return validateHourlyFrame(batch)
}
