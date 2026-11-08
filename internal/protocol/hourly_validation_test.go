package protocol

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestHourlyUserRequiresImmutableFinancialBindingAndPaidBoundary(t *testing.T) {
	paid := time.Date(2026, 11, 9, 2, 0, 0, 0, time.UTC)
	user := User{ID: 1, Hourly: &HourlyUser{Owner: HourlyOwner{ID: "owner", Generation: 1}, EnrollmentID: "enrollment"}, AccountingPeriod: "period", ValidUntil: &paid}
	if err := ValidateHourlyUser(user); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*User){
		func(u *User) { u.ValidUntil = nil },
		func(u *User) { zero := time.Time{}; u.ValidUntil = &zero },
		func(u *User) { u.AccountingPeriod = "" },
		func(u *User) { u.Hourly.EnrollmentID = "" },
		func(u *User) { u.Hourly.Owner.Generation = math.MaxInt64 + 1 },
		func(u *User) { u.Hourly.Owner.ID = "_xnode_reserved" },
	} {
		invalid := Clone(user)
		change(&invalid)
		if err := ValidateHourlyUser(invalid); err == nil {
			t.Fatal("hourly financial binding accepted after required term removed")
		}
	}
	if err := ValidateHourlyUser(User{}); err != nil {
		t.Fatal("legacy user unexpectedly requires hourly fields", err)
	}
}

func TestHourlyGrantRejectsUnboundedAndMalformedWireTerms(t *testing.T) {
	grant := HourlyGrant{SessionID: hourlyWireStream, Owner: HourlyOwner{ID: "owner", Generation: 1}, Nonce: hourlyWireStream, Sequence: 1, DayUTC: "2026-11-09", LifetimeMillis: 10000, RateBytesPerSecond: 1_000_000, BurstBytes: 16384}
	if err := ValidateHourlyGrant(grant); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*HourlyGrant){
		func(g *HourlyGrant) { g.SessionID = "other" },
		func(g *HourlyGrant) { g.Nonce = strings.ToUpper(hourlyWireStream[:31] + "a") },
		func(g *HourlyGrant) { g.Sequence = 0 },
		func(g *HourlyGrant) { g.Sequence = math.MaxInt64 + 1 },
		func(g *HourlyGrant) { g.DayUTC = "2026-02-30" },
		func(g *HourlyGrant) { g.LifetimeMillis = 0 },
		func(g *HourlyGrant) { g.LifetimeMillis = 10001 },
		func(g *HourlyGrant) { g.BurstBytes = 16385 },
		func(g *HourlyGrant) { g.RateBytesPerSecond = 1_000_000_000_001 },
	} {
		invalid := grant
		change(&invalid)
		if err := ValidateHourlyGrant(invalid); err == nil {
			t.Fatal("invalid grant term accepted")
		}
	}
}

func TestHourlyDemandBoundsDuplicateOwnersAndProgress(t *testing.T) {
	demand := HourlyDemand{Owner: HourlyOwner{ID: "owner", Generation: 1}, Nonce: hourlyWireStream, LifetimeMillis: 10000, PendingBytes: 16384, MinAtomicBytes: 16384}
	batch := HourlyDemandBatch{SessionID: hourlyWireStream, Demands: []HourlyDemand{demand}}
	if err := ValidateHourlyDemandBatch(batch); err != nil {
		t.Fatal(err)
	}
	batch.Demands = append(batch.Demands, demand)
	if err := ValidateHourlyDemandBatch(batch); err == nil {
		t.Fatal("duplicate owner demand accepted")
	}
	batch.Demands = []HourlyDemand{demand}
	batch.Demands[0].MinAtomicBytes = 16385
	if err := ValidateHourlyDemandBatch(batch); err == nil {
		t.Fatal("indivisible demand exceeded aggregate burst bound")
	}
	batch.Demands = []HourlyDemand{}
	progress := HourlyCreditProgress{ReservationID: "reservation", IssueSequence: 1, AdmittedUploadBytes: 1}
	batch.Progress = []HourlyCreditProgress{progress}
	if err := ValidateHourlyDemandBatch(batch); err != nil {
		t.Fatal("progress-only batch rejected", err)
	}
	batch.Progress = append(batch.Progress, progress)
	if err := ValidateHourlyDemandBatch(batch); err == nil {
		t.Fatal("duplicate credit progress accepted")
	}
	batch.Progress = nil
	if err := ValidateHourlyDemandBatch(batch); err == nil {
		t.Fatal("empty demand/progress batch accepted")
	}
}

func TestHourlySamplesRejectOverflowAndUnorderedCoverage(t *testing.T) {
	at := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	sample := HourlySample{CounterGeneration: 1, Owner: HourlyOwner{ID: "owner", Generation: 1}, EnrollmentID: "enrollment", UserID: 1, AccountingPeriod: "period", DayUTC: "2026-11-09", From: at, Through: at, UploadBytes: math.MaxInt64}
	if err := ValidateHourlySample(sample); err != nil {
		t.Fatal(err)
	}
	sample.DownloadBytes = 1
	if err := ValidateHourlySample(sample); err == nil {
		t.Fatal("overflowing upload-plus-download sample accepted")
	}
	sample.DownloadBytes, sample.Through = 0, at.Add(-time.Second)
	if err := ValidateHourlySample(sample); err == nil {
		t.Fatal("inverted coverage accepted")
	}
}
