package protocol

import "reflect"

func firewallPortsSchema(t reflect.Type, schema map[string]any) map[string]any {
	properties := schema["properties"].(map[string]any)
	if t == reflect.TypeOf(PortRange{}) {
		for _, name := range []string{"from", "to"} {
			properties[name] = map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}
		}
	}
	if t == reflect.TypeOf(Forward{}) {
		for _, name := range []string{"port", "target_port", "port_end", "target_port_end"} {
			minimum := 1
			if name == "port_end" || name == "target_port_end" {
				minimum = 0
			}
			properties[name] = map[string]any{"type": "integer", "minimum": minimum, "maximum": 65535}
		}
	}
	return schema
}
