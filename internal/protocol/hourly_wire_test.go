package protocol

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

const hourlyWireStream = "11111111111111111111111111111111"

func hourlyWireInstall() HourlyCreditInstall {
	return HourlyCreditInstall{ReservationID: "reservation-one", IssueSequence: 9007199254740993, Owner: HourlyOwner{ID: "owner-one", Generation: 9007199254740993}, DayUTC: "2026-11-09", AgentID: hourlyWireStream, BootID: hourlyWireStream, SessionID: hourlyWireStream, ByteCeiling: math.MaxInt64, Kind: "extra"}
}

func TestHourlyWirePreservesLargeDecimalStrings(t *testing.T) {
	install := hourlyWireInstall()
	if err := ValidateHourlyInstall(install); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(install)
	if err != nil {
		t.Fatal(err)
	}
	for _, literal := range []string{`"issue_sequence":"9007199254740993"`, `"generation":"9007199254740993"`, `"byte_ceiling":"9223372036854775807"`} {
		if !strings.Contains(string(raw), literal) {
			t.Fatal("wire lost exact decimal-string quantity", literal)
		}
	}
	var decoded HourlyCreditInstall
	if err = Decode(raw, &decoded); err != nil || decoded != install {
		t.Fatal("installation roundtrip changed obligation", err)
	}
	for _, invalid := range []string{strings.Replace(string(raw), `"issue_sequence":"9007199254740993"`, `"issue_sequence":9007199254740993`, 1), strings.Replace(string(raw), `"kind":"extra"`, `"kind":"extra","unknown":true`, 1)} {
		if err = Decode([]byte(invalid), &decoded); err == nil {
			t.Fatal("non-string counter or unknown wire field accepted")
		}
	}
	at := time.Date(2026, 11, 9, 1, 0, 0, 0, time.UTC)
	sample := HourlySample{Owner: install.Owner, EnrollmentID: "enrollment", UserID: 9007199254740993, AccountingPeriod: "period", CounterGeneration: math.MaxInt64, DayUTC: install.DayUTC, From: at, Through: at, UploadBytes: 9007199254740993}
	raw, err = json.Marshal(sample)
	if err != nil || !strings.Contains(string(raw), `"user_id":"9007199254740993"`) || !strings.Contains(string(raw), `"upload_bytes":"9007199254740993"`) {
		t.Fatal("hourly sample loses exact principal/counter encoding", err)
	}
	var sampleDecoded HourlySample
	if err = Decode(raw, &sampleDecoded); err != nil || !reflect.DeepEqual(sample, sampleDecoded) {
		t.Fatal("hourly sample roundtrip changed identity", err)
	}
}

func TestHourlySchemaRequiresPaidIdentityAcrossAllUserMutations(t *testing.T) {
	for _, value := range []any{User{}, UsersSync{}, UsersDelta{}, Config{}} {
		schema := Schema(value)
		if _, direct := value.(User); !direct {
			fields := schema["properties"].(map[string]any)
			key := "users"
			if _, delta := value.(UsersDelta); delta {
				key = "upsert"
			}
			schema = fields[key].(map[string]any)["items"].(map[string]any)
		}
		conditions := schema["allOf"].([]any)
		required := conditions[0].(map[string]any)["then"].(map[string]any)["required"].([]string)
		if !reflect.DeepEqual(required, []string{"accounting_period", "valid_until"}) {
			t.Fatal("hourly user schema omits paid identity", reflect.TypeOf(value))
		}
	}
	for _, key := range []string{"counter_generation", "user_id", "upload_bytes", "download_bytes"} {
		field := HourlySchemas()["sample"].(map[string]any)["properties"].(map[string]any)[key].(map[string]any)
		if field["type"] != "string" {
			t.Fatal("hourly schema loses exact integer precision", key)
		}
	}
}

func TestHourlyCreditCommandsHaveTypedMutationContractsAndBoundedExecution(t *testing.T) {
	command := Schemas()["master_message"].(map[string]any)["oneOf"].([]any)
	var found map[string]any
	for _, variant := range command {
		fields := variant.(map[string]any)["properties"].(map[string]any)
		if fields["type"].(map[string]any)["const"] == "command" {
			found = fields["data"].(map[string]any)
		}
	}
	if found == nil {
		t.Fatal("command envelope absent")
	}
	conditions := found["allOf"].([]any)
	for _, name := range []string{HourlyCreditInstallCommand, HourlyCreditSealCommand, HourlyCreditAckCommand} {
		if ClassifyAction(name) != UtilityAction {
			t.Fatal("credit I/O/drain entered the reserved traffic-control executor", name)
		}
		want := 30 * time.Second
		if name == HourlyCreditSealCommand {
			want = 2 * time.Minute
		}
		if CommandTimeout(name) != want {
			t.Fatal("credit command timeout unbounded or incorrect", name)
		}
		present := false
		for _, condition := range conditions {
			entry := condition.(map[string]any)
			if entry["if"].(map[string]any)["properties"].(map[string]any)["name"].(map[string]any)["const"] == name {
				args := entry["then"].(map[string]any)["properties"].(map[string]any)["args"].(map[string]any)
				present = args["additionalProperties"] == false
			}
		}
		if !present {
			t.Fatal("credit command has no closed typed argument schema", name)
		}
	}
}
