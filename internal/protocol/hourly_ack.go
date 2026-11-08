package protocol

import (
	"errors"
	"math"
)

func ValidateHourlyGrantAck(ack HourlyGrantAck) error {
	if !ValidStreamID(ack.SessionID) || ValidateHourlyOwner(ack.Owner) != nil || !ValidStreamID(ack.Nonce) || ack.Sequence == 0 || ack.Sequence > math.MaxInt64 || len(ack.Reason) > 128 {
		return errors.New("invalid hourly grant acknowledgment")
	}
	return nil
}

func ValidateHourlyGrantAckBatch(batch HourlyGrantAckBatch) error {
	if !ValidStreamID(batch.SessionID) || len(batch.Acks) == 0 || len(batch.Acks) > MaxHourlyItems {
		return errors.New("invalid hourly grant acknowledgment batch")
	}
	seen := map[HourlyOwner]bool{}
	for _, ack := range batch.Acks {
		if ValidateHourlyGrantAck(ack) != nil || ack.SessionID != batch.SessionID || seen[ack.Owner] {
			return errors.New("invalid or repeated hourly grant acknowledgment")
		}
		seen[ack.Owner] = true
	}
	return validateHourlyFrame(batch)
}
