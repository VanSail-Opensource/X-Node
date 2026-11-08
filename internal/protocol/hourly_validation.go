package protocol

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
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
	if !ValidStreamID(batch.SessionID) || len(batch.Demands) > MaxHourlyItems || len(batch.Progress) > MaxHourlyItems || len(batch.Demands)+len(batch.Progress) == 0 {
		return errors.New("invalid hourly demand batch")
	}
	owners, credits := map[string]bool{}, map[string]bool{}
	for _, demand := range batch.Demands {
		key := demand.Owner.ID + ":" + strconv.FormatUint(demand.Owner.Generation, 10)
		if ValidateHourlyDemand(demand) != nil || owners[key] {
			return errors.New("invalid or duplicate hourly demand")
		}
		owners[key] = true
	}
	for _, progress := range batch.Progress {
		if ValidateHourlyProgress(progress) != nil || credits[progress.ReservationID] {
			return errors.New("invalid or duplicate hourly progress")
		}
		credits[progress.ReservationID] = true
	}
	return validateHourlyFrame(batch)
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
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > MaxHourlyFrameBytes {
		return errors.New("hourly frame capacity exceeded")
	}
	return nil
}
