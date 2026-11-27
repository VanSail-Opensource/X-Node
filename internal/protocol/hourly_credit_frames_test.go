package protocol

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func fixtureCreditProofs(n, idLength int) []HourlyCreditProof {
	proofs := make([]HourlyCreditProof, n)
	for i := range proofs {
		install := hourlyWireInstall()
		install.ReservationID = strings.Repeat("r", idLength) + fmt.Sprintf("-%04d", i)
		install.Owner.ID = strings.Repeat("o", idLength)
		install.IssueSequence = uint64(i + 1)
		install.ByteCeiling = 1000
		proof := HourlyCreditProof{Install: install, AdmittedDownloadBytes: 50, UnusedBytes: 950}
		if i%2 == 0 {
			proof.Recovery, proof.AdmittedDownloadBytes, proof.UnusedBytes, proof.UnknownBytes = true, 0, 0, 1000
		}
		proof.Digest = HourlyProofDigest(proof)
		proofs[i] = proof
	}
	return proofs
}

func TestHourlyProofFramesLimitsOrderAndWire(t *testing.T) {
	for _, tc := range []struct {
		name     string
		idLength int
	}{
		{"item_limit", 1},
		{"byte_limit", 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := fixtureCreditProofs(300, tc.idLength)
			frames, err := HourlyProofFrames(want)
			if err != nil || len(frames) < 3 {
				t.Fatalf("packed frames: %d, %v", len(frames), err)
			}
			offset := 0
			for i, frame := range frames {
				var batch HourlyCreditProofBatch
				if frame.Type != "hourly.credit.proofs" || frame.V != Version || len(frame.Data) > MaxHourlyFrameBytes {
					t.Fatalf("invalid frame envelope: type=%q version=%d bytes=%d", frame.Type, frame.V, len(frame.Data))
				}
				if err := Decode(frame.Data, &batch); err != nil {
					t.Fatal(err)
				}
				if err := ValidateHourlyProofBatch(batch); err != nil {
					t.Fatal(err)
				}
				end := offset + len(batch.Proofs)
				if end > len(want) {
					t.Fatal("extra proof")
				}
				for index, proof := range batch.Proofs {
					if proof != want[offset+index] {
						t.Fatalf("changed or reordered proof at %d", offset+index)
					}
				}
				if !bytes.Equal(frame.Data, New("hourly.credit.proofs", "", 0, batch).Data) {
					t.Fatal("packed JSON changed the wire shape")
				}
				if i != len(frames)-1 && len(batch.Proofs) < MaxHourlyItems {
					if end == len(want) {
						t.Fatal("unexpected additional frame")
					}
					extended := HourlyCreditProofBatch{Proofs: want[offset : end+1]}
					if len(New("hourly.credit.proofs", "", 0, extended).Data) <= MaxHourlyFrameBytes {
						t.Fatal("frame split below item and byte limits")
					}
				}
				if i == 0 && (len(batch.Proofs) == MaxHourlyItems) != (tc.name == "item_limit") {
					t.Fatal("test did not exercise its intended limit", len(batch.Proofs))
				}
				offset = end
			}
			if offset != len(want) {
				t.Fatalf("read %d of %d proofs", offset, len(want))
			}
		})
	}
}

func TestHourlyProofFramesRejectLateInvalidOrDuplicateProof(t *testing.T) {
	if frames, err := HourlyProofFrames(nil); len(frames) != 0 || err != nil {
		t.Fatal("empty recovery emitted a frame", err)
	}
	proofs := fixtureCreditProofs(200, 120)
	proofs[len(proofs)-1].Digest = "invalid"
	if frames, err := HourlyProofFrames(proofs); frames != nil || err == nil {
		t.Fatal("invalid digest returned partial authority")
	}
	proofs[len(proofs)-1] = proofs[0]
	if frames, err := HourlyProofFrames(proofs); frames != nil || err == nil {
		t.Fatal("duplicate across frames was accepted")
	}
}

func TestHourlyDemandFrameMatchesValidationAndEncoding(t *testing.T) {
	batch := HourlyDemandBatch{SessionID: hourlyWireStream, Demands: []HourlyDemand{}, Progress: []HourlyCreditProgress{{ReservationID: "credit", IssueSequence: 1}}}
	frame, err := HourlyDemandFrame(batch)
	want := New("hourly.demand", "", 0, batch)
	if err != nil || frame.Type != want.Type || frame.V != want.V || !bytes.Equal(frame.Data, want.Data) {
		t.Fatal("demand wire changed", err)
	}
	batch.Progress = append(batch.Progress, batch.Progress[0])
	if m, err := HourlyDemandFrame(batch); err == nil || len(m.Data) != 0 {
		t.Fatal("duplicate credit progress was encoded")
	}
}

func BenchmarkPackHourlyProofs(b *testing.B) {
	proofs := fixtureCreditProofs(512, 32)
	b.Run("prefix_validation", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var frames []Message
			var batch HourlyCreditProofBatch
			for _, proof := range proofs {
				batch.Proofs = append(batch.Proofs, proof)
				if ValidateHourlyProofBatch(batch) != nil {
					batch.Proofs = batch.Proofs[:len(batch.Proofs)-1]
					frames = append(frames, New("hourly.credit.proofs", "", 0, batch))
					batch.Proofs = []HourlyCreditProof{proof}
				}
			}
			frames = append(frames, New("hourly.credit.proofs", "", 0, batch))
			if len(frames) < 4 {
				b.Fatal("failed to pack the fixture")
			}
		}
	})
	b.Run("single_pass", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if frames, err := HourlyProofFrames(proofs); len(frames) < 4 || err != nil {
				b.Fatal("failed to pack the fixture", err)
			}
		}
	})
}
