package protocol

import (
	"encoding/json"
	"testing"
)

func TestHourlySealExpectedInstallRemainsBoundToExactReservation(t *testing.T) {
	i := HourlyCreditInstall{ReservationID: "credit", IssueSequence: 1, Owner: HourlyOwner{ID: "account", Generation: 7}, DayUTC: "2026-11-09", AgentID: "11111111111111111111111111111111", BootID: "22222222222222222222222222222222", SessionID: "33333333333333333333333333333333", ByteCeiling: 1000, Kind: "free"}
	seal := HourlyCreditSeal{ReservationID: i.ReservationID, Expected: &i}
	if err := ValidateHourlySeal(seal); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HourlyCreditSeal
	if err = Decode(raw, &decoded); err != nil || decoded.Expected == nil || *decoded.Expected != i {
		t.Fatal("expected obligation did not round trip", err)
	}
	seal.ReservationID = "different-credit"
	if ValidateHourlySeal(seal) == nil {
		t.Fatal("seal could reclaim another reservation")
	}
	seal.ReservationID = i.ReservationID
	i.ByteCeiling = 0
	if ValidateHourlySeal(seal) == nil {
		t.Fatal("invalid expected install accepted")
	}
	if err = ValidateHourlySeal(HourlyCreditSeal{ReservationID: "credit"}); err != nil {
		t.Fatal("ordinary existing-credit seal lost compatibility", err)
	}
}
