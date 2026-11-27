package protocol

import (
	"encoding/json"
	"errors"
	"math"
	"time"
)

func ValidateHourlyOwner(owner HourlyOwner) error {
	if !ValidName(owner.ID) || owner.Generation > math.MaxInt64 {
		return errors.New("invalid hourly owner")
	}
	return nil
}

func ValidHourlyDay(day string) bool {
	at, err := time.Parse("2006-01-02", day)
	return err == nil && at.Format("2006-01-02") == day
}

func ValidateHourlyUser(user User) error {
	if user.Hourly == nil {
		return nil
	}
	if ValidateHourlyOwner(user.Hourly.Owner) != nil || !ValidName(user.Hourly.EnrollmentID) || !ValidName(user.AccountingPeriod) || user.ValidUntil == nil || user.ValidUntil.IsZero() {
		return errors.New("hourly identity requires owner, enrollment, period and paid expiry")
	}
	return nil
}

func ValidateHourlyDemand(demand HourlyDemand) error {
	if ValidateHourlyOwner(demand.Owner) != nil || !ValidStreamID(demand.Nonce) || demand.LifetimeMillis == 0 || demand.LifetimeMillis > MaxHourlyLifetimeMillis || demand.PendingBytes > math.MaxInt64 || demand.MinAtomicBytes > MaxHourlyBurstBytes || demand.PendingBytes > 0 && demand.MinAtomicBytes == 0 {
		return errors.New("invalid hourly demand")
	}
	return nil
}

func ValidateHourlyDemandBatch(batch HourlyDemandBatch) error {
	_, err := HourlyDemandFrame(batch)
	return err
}

// HourlyDemandFrame validates and returns the same payload it size-checked.
func HourlyDemandFrame(batch HourlyDemandBatch) (Message, error) {
	if !ValidStreamID(batch.SessionID) || len(batch.Demands) > MaxHourlyItems || len(batch.Progress) > MaxHourlyItems || len(batch.Demands)+len(batch.Progress) == 0 {
		return Message{}, errors.New("invalid hourly demand batch")
	}
	owners := make(map[HourlyOwner]struct{}, len(batch.Demands))
	credits := make(map[string]struct{}, len(batch.Progress))
	for _, demand := range batch.Demands {
		if _, duplicate := owners[demand.Owner]; duplicate || ValidateHourlyDemand(demand) != nil {
			return Message{}, errors.New("invalid or duplicate hourly demand")
		}
		owners[demand.Owner] = struct{}{}
	}
	for _, progress := range batch.Progress {
		if _, duplicate := credits[progress.ReservationID]; duplicate || ValidateHourlyProgress(progress) != nil {
			return Message{}, errors.New("invalid or duplicate hourly progress")
		}
		credits[progress.ReservationID] = struct{}{}
	}
	data, err := marshalHourlyFrame(batch)
	if err != nil {
		return Message{}, err
	}
	return Message{V: Version, Type: "hourly.demand", Data: data}, nil
}

func ValidateHourlyGrant(grant HourlyGrant) error {
	if ValidateHourlyOwner(grant.Owner) != nil || !ValidStreamID(grant.SessionID) || !ValidStreamID(grant.Nonce) || grant.Sequence == 0 || grant.Sequence > math.MaxInt64 || !ValidHourlyDay(grant.DayUTC) || grant.LifetimeMillis == 0 || grant.LifetimeMillis > MaxHourlyLifetimeMillis || grant.BurstBytes > MaxHourlyBurstBytes || grant.RateBytesPerSecond > 1_000_000_000_000 {
		return errors.New("invalid hourly grant")
	}
	return nil
}

func ValidateHourlySample(sample HourlySample) error {
	if ValidateHourlyOwner(sample.Owner) != nil || !ValidName(sample.EnrollmentID) || sample.UserID <= 0 || !ValidName(sample.AccountingPeriod) || !ValidHourlyDay(sample.DayUTC) || sample.CounterGeneration == 0 || sample.From.IsZero() || sample.Through.Before(sample.From) || sample.UploadBytes > math.MaxInt64 || sample.DownloadBytes > math.MaxInt64-sample.UploadBytes {
		return errors.New("invalid hourly admitted sample")
	}
	return nil
}

func validateHourlyFrame(value any) error {
	_, err := marshalHourlyFrame(value)
	return err
}

func marshalHourlyFrame(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxHourlyFrameBytes {
		return nil, errors.New("hourly frame capacity exceeded")
	}
	return encoded, nil
}
