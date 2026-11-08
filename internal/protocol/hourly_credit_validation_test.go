package protocol

import (
	"strconv"
	"testing"
)

func TestHourlyCreditProofConservesObligationAndDistinguishesRecovery(t *testing.T) {
	install := hourlyWireInstall()
	install.ByteCeiling = 100
	proof := HourlyCreditProof{Install: install, AdmittedUploadBytes: 20, AdmittedDownloadBytes: 30, UnusedBytes: 50}
	proof.Digest = HourlyProofDigest(proof)
	if err := ValidateHourlyProof(proof); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*HourlyCreditProof){
		func(p *HourlyCreditProof) { p.UnusedBytes-- },
		func(p *HourlyCreditProof) { p.AdmittedUploadBytes = 101 },
		func(p *HourlyCreditProof) { p.UnknownBytes, p.UnusedBytes = 1, 49 },
		func(p *HourlyCreditProof) { p.Recovery = true },
	} {
		invalid := proof
		change(&invalid)
		invalid.Digest = HourlyProofDigest(invalid)
		if err := ValidateHourlyProof(invalid); err == nil {
			t.Fatal("non-conserving or fabricated recovery proof accepted")
		}
	}
	recovery := proof
	recovery.Recovery, recovery.UnusedBytes, recovery.UnknownBytes = true, 0, 50
	recovery.Digest = HourlyProofDigest(recovery)
	if err := ValidateHourlyProof(recovery); err != nil {
		t.Fatal("honest unknown residual rejected", err)
	}
	recovery.AdmittedUploadBytes++
	if err := ValidateHourlyProof(recovery); err == nil {
		t.Fatal("modified proof retained a valid digest")
	}
}

func TestHourlyCreditProofBatchIsUniqueAndBoundedBySerializedBytes(t *testing.T) {
	install := hourlyWireInstall()
	install.ByteCeiling = 100
	proof := HourlyCreditProof{Install: install, UnusedBytes: 100}
	proof.Digest = HourlyProofDigest(proof)
	if err := ValidateHourlyProofBatch(HourlyCreditProofBatch{Proofs: []HourlyCreditProof{proof, proof}}); err == nil {
		t.Fatal("duplicate financial proof accepted")
	}
	batch := HourlyCreditProofBatch{Proofs: make([]HourlyCreditProof, MaxHourlyItems)}
	for i := range batch.Proofs {
		entry := proof
		entry.Install.ReservationID += "-" + strconv.Itoa(i)
		entry.Install.IssueSequence += uint64(i)
		entry.Digest = HourlyProofDigest(entry)
		batch.Proofs[i] = entry
	}
	if err := ValidateHourlyProofBatch(batch); err == nil {
		t.Fatal("financial batch ignored the 64 KiB serialized frame limit")
	}
}
