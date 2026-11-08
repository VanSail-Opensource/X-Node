package protocol

import "reflect"

func hourlySchema(t reflect.Type, schema map[string]any) map[string]any {
	fields := schema["properties"].(map[string]any)
	name := func(key string) { fields[key].(map[string]any)["pattern"] = "^(?!_xnode_)[A-Za-z0-9._-]{1,128}$" }
	stream := func(key string) { fields[key].(map[string]any)["pattern"] = "^[0-9a-f]{32}$" }
	day := func(key string) { fields[key].(map[string]any)["format"] = "date" }
	positive := func(key string) { fields[key].(map[string]any)["pattern"] = "^[1-9][0-9]*$" }
	bounded := func(key string, low, high int) {
		field := fields[key].(map[string]any)
		field["minimum"], field["maximum"] = low, high
	}
	switch t {
	case reflect.TypeOf(User{}):
		schema["allOf"] = []any{map[string]any{"if": map[string]any{"required": []string{"hourly"}}, "then": map[string]any{"required": []string{"accounting_period", "valid_until"}, "properties": map[string]any{"accounting_period": map[string]any{"minLength": 1}}}}}
	case reflect.TypeOf(HourlyOwner{}):
		name("id")
	case reflect.TypeOf(HourlyUser{}):
		name("enrollment_id")
	case reflect.TypeOf(HourlyDemand{}):
		stream("nonce")
		bounded("lifetime_ms", 1, MaxHourlyLifetimeMillis)
		bounded("min_atomic_bytes", 0, MaxHourlyBurstBytes)
	case reflect.TypeOf(HourlyDemandBatch{}):
		stream("session_id")
		fields["demands"].(map[string]any)["maxItems"] = MaxHourlyItems
		fields["progress"].(map[string]any)["maxItems"] = MaxHourlyItems
		schema["anyOf"] = []any{map[string]any{"properties": map[string]any{"demands": map[string]any{"minItems": 1}}}, map[string]any{"required": []string{"progress"}, "properties": map[string]any{"progress": map[string]any{"minItems": 1}}}}
	case reflect.TypeOf(HourlyGrant{}):
		stream("session_id")
		stream("nonce")
		day("day_utc")
		positive("sequence")
		bounded("lifetime_ms", 1, MaxHourlyLifetimeMillis)
		bounded("burst_bytes", 0, MaxHourlyBurstBytes)
	case reflect.TypeOf(HourlyGrantAck{}):
		stream("session_id")
		stream("nonce")
		positive("sequence")
	case reflect.TypeOf(HourlyGrantAckBatch{}):
		stream("session_id")
		field := fields["acks"].(map[string]any)
		field["minItems"], field["maxItems"] = 1, MaxHourlyItems
	case reflect.TypeOf(HourlySample{}):
		positive("counter_generation")
		name("enrollment_id")
		name("accounting_period")
		day("day_utc")
		positive("user_id")
	case reflect.TypeOf(HourlyCreditInstall{}):
		name("reservation_id")
		positive("issue_sequence")
		positive("byte_ceiling")
		day("day_utc")
		stream("agent_id")
		stream("boot_id")
		stream("session_id")
		fields["kind"].(map[string]any)["enum"] = []string{"free", "extra"}
	case reflect.TypeOf(HourlyCreditProgress{}):
		name("reservation_id")
		positive("issue_sequence")
	case reflect.TypeOf(HourlyCreditSeal{}):
		name("reservation_id")
	case reflect.TypeOf(HourlyCreditAck{}):
		name("reservation_id")
		positive("issue_sequence")
		fields["digest"].(map[string]any)["pattern"] = "^[0-9a-fA-F]{64}$"
	case reflect.TypeOf(HourlyCreditProof{}):
		fields["digest"].(map[string]any)["pattern"] = "^[0-9a-f]{64}$"
	case reflect.TypeOf(HourlyCreditProofBatch{}):
		field := fields["proofs"].(map[string]any)
		field["minItems"], field["maxItems"] = 1, MaxHourlyItems
	}
	return schema
}

func addHourlyCommandSchemas(command map[string]any) {
	values := map[string]any{HourlyCreditInstallCommand: HourlyCreditInstall{}, HourlyCreditSealCommand: HourlyCreditSeal{}, HourlyCreditAckCommand: HourlyCreditAck{}}
	for _, name := range []string{HourlyCreditInstallCommand, HourlyCreditSealCommand, HourlyCreditAckCommand} {
		value := values[name]
		condition := map[string]any{"if": map[string]any{"properties": map[string]any{"name": map[string]any{"const": name}}}, "then": map[string]any{"required": []string{"args"}, "properties": map[string]any{"args": Schema(value)}}}
		command["allOf"] = append(command["allOf"].([]any), condition)
	}
}

// HourlySchemas publishes independently negotiated messages and durable credit
// commands. Validation also enforces conservation, uniqueness and frame bounds.
func HourlySchemas() map[string]any {
	return map[string]any{"grant": Schema(HourlyGrant{}), "demand": Schema(HourlyDemandBatch{}), "grant_ack": Schema(HourlyGrantAck{}), "grant_acks": Schema(HourlyGrantAckBatch{}), "credit_install": Schema(HourlyCreditInstall{}), "credit_seal": Schema(HourlyCreditSeal{}), "credit_ack": Schema(HourlyCreditAck{}), "credit_proofs": Schema(HourlyCreditProofBatch{}), "sample": Schema(HourlySample{})}
}
