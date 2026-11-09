package protocol

import "reflect"

func certificateTypeSchema(t reflect.Type, schema map[string]any) map[string]any {
	if t == reflect.TypeOf(Config{}) {
		schema["properties"].(map[string]any)["certificates"].(map[string]any)["maxProperties"] = MaxCertificateProfiles
	}
	return schema
}

func addCertificateCommandSchema(command map[string]any) {
	args := Schema(CertificateRunArgs{})
	properties := args["properties"].(map[string]any)
	properties["action"] = map[string]any{"type": "string", "enum": []string{"issue", "renew"}}
	properties["profile_id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 128}
	properties["expected_revision"] = map[string]any{"type": "integer", "minimum": 1}
	command["allOf"] = append(command["allOf"].([]any), map[string]any{
		"if":   map[string]any{"properties": map[string]any{"name": map[string]any{"const": CertificateRunCommand}}},
		"then": map[string]any{"required": []string{"args"}, "properties": map[string]any{"args": args}},
	})
}
