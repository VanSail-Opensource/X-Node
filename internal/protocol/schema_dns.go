package protocol

import "reflect"

func dnsSchema(t reflect.Type, schema map[string]any) map[string]any {
	if t != reflect.TypeOf(DDNSJob{}) {
		return schema
	}
	properties := schema["properties"].(map[string]any)
	properties["id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": `^[A-Za-z0-9._-]+$`}
	properties["generation"] = map[string]any{"type": "string", "maxLength": 128, "pattern": `^[A-Za-z0-9._-]*$`}
	properties["ttl_seconds"] = map[string]any{"type": "integer", "minimum": 0, "maximum": MaxDDNSTTLSeconds}
	properties["interval_seconds"] = map[string]any{"type": "integer", "minimum": 0, "maximum": 86400}
	schema["anyOf"] = []any{
		map[string]any{"required": []string{"ipv4"}, "properties": map[string]any{"ipv4": map[string]any{"type": "string", "minLength": 1}}},
		map[string]any{"required": []string{"ipv6"}, "properties": map[string]any{"ipv6": map[string]any{"type": "string", "minLength": 1}}},
	}
	return schema
}
