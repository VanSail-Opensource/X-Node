package protocol

import "testing"

func TestHourlyAcknowledgmentBatchCannotCrossScopeOrRepeatOwner(t *testing.T) {
	ack := HourlyGrantAck{SessionID: hourlyWireStream, Owner: HourlyOwner{ID: "owner"}, Nonce: hourlyWireStream, Sequence: 1, Applied: true}
	batch := HourlyGrantAckBatch{SessionID: hourlyWireStream, Acks: []HourlyGrantAck{ack}}
	if err := ValidateHourlyGrantAckBatch(batch); err != nil {
		t.Fatal(err)
	}
	batch.Acks = append(batch.Acks, ack)
	if ValidateHourlyGrantAckBatch(batch) == nil {
		t.Fatal("duplicate owner acknowledgment accepted")
	}
	batch.Acks = batch.Acks[:1]
	batch.Acks[0].SessionID = "22222222222222222222222222222222"
	if ValidateHourlyGrantAckBatch(batch) == nil {
		t.Fatal("acknowledgment crossed control sessions")
	}
	if ValidateHourlyGrantAckBatch(HourlyGrantAckBatch{SessionID: hourlyWireStream}) == nil {
		t.Fatal("empty acknowledgment batch accepted")
	}
}
