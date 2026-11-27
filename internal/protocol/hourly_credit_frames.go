package protocol

import (
	"encoding/json"
	"errors"
)

// HourlyProofFrames packs ordered immutable proofs without revalidating or
// reencoding every prefix. Size is measured on the actual JSON payload, as
// in ValidateHourlyProofBatch. In the event of an invalid proof no partial
// result is returned.
func HourlyProofFrames(proofs []HourlyCreditProof) ([]Message, error) {
	if len(proofs) == 0 {
		return nil, nil
	}
	const prefix, suffix = `{"proofs":[`, `]}`
	var frames []Message
	var data []byte
	count := 0
	flush := func() {
		frames = append(frames, Message{V: Version, Type: "hourly.credit.proofs", Data: append(data, suffix...)})
		data, count = nil, 0
	}
	seen := make(map[string]struct{}, len(proofs))
	for i, proof := range proofs {
		id := proof.Install.ReservationID
		if _, duplicate := seen[id]; duplicate || ValidateHourlyProof(proof) != nil {
			return nil, errors.New("invalid or duplicate hourly proof")
		}
		seen[id] = struct{}{}
		encoded, err := json.Marshal(proof)
		if err != nil || len(prefix)+len(encoded)+len(suffix) > MaxHourlyFrameBytes {
			return nil, errors.New("hourly proof exceeds frame capacity")
		}
		if count > 0 && (count == MaxHourlyItems || len(data)+1+len(encoded)+len(suffix) > MaxHourlyFrameBytes) {
			flush()
		}
		if count == 0 {
			capacity := min(MaxHourlyFrameBytes, len(prefix)+len(suffix)+min(len(proofs)-i, MaxHourlyItems)*(len(encoded)+1))
			data = append(make([]byte, 0, capacity), prefix...)
		} else {
			data = append(data, ',')
		}
		data = append(data, encoded...)
		count++
	}
	flush()
	return frames, nil
}
