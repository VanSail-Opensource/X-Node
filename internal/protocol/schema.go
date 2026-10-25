package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

func Schema(value any) map[string]any { return schemaType(reflect.TypeOf(value)) }
func schemaType(t reflect.Type) map[string]any {
	if t == nil {
		return map[string]any{}
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return map[string]any{"type": "object"}
	}
	switch t.Kind() {
	case reflect.Struct:
		properties := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" || f.PkgPath != "" {
				continue
			}
			parts := strings.Split(tag, ",")
			name := parts[0]
			if name == "" {
				name = f.Name
			}
			properties[name] = schemaType(f.Type)
			if !strings.Contains(tag, "omitempty") {
				required = append(required, name)
			}
		}
		return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaType(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaType(t.Elem())}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	default:
		return map[string]any{}
	}
}
func Schemas() map[string]any {
	root := Schema(Config{})
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["$id"] = "https://github.com/VanSail-Opensource/X-Node/config.schema.json"
	root["title"] = "X-Node remote configuration"
	user := schemaType(reflect.TypeOf(User{}))
	properties := user["properties"].(map[string]any)
	properties["id"].(map[string]any)["minimum"] = 1
	properties["inbound_tags"].(map[string]any)["minItems"] = 1
	properties["inbound_tags"].(map[string]any)["uniqueItems"] = true
	for _, name := range []string{"active_ip_limit", "connection_limit", "speed_limit_mbps", "burst_speed_limit_mbps", "speed_limit_after_seconds", "speed_limit_reset_seconds"} {
		properties[name].(map[string]any)["minimum"] = 0
	}
	user["anyOf"] = []any{map[string]any{"required": []string{"uuid"}}, map[string]any{"required": []string{"credentials"}}}
	root["properties"].(map[string]any)["users"].(map[string]any)["items"] = user
	types := map[string]any{"state.sync": root, "config.apply": root, "users.sync": Schema(UsersSync{}), "users.delta": Schema(UsersDelta{}), "user.controls": Schema(UserControls{}), "firewall.events.ack": Schema(FirewallEventAck{}), "traffic.ack": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}, "additionalProperties": false}, "command": map[string]any{"type": "object", "required": []string{"name"}, "properties": map[string]any{"name": map[string]any{"type": "string", "enum": CommandNames}, "args": map[string]any{"type": "object"}}, "additionalProperties": false}, "command.cancel": map[string]any{"type": "object", "required": []string{"id"}, "properties": map[string]any{"id": map[string]any{"type": "string"}}, "additionalProperties": false}}
	command := types["command"].(map[string]any)
	types["ddns.changes.ack"] = Schema(DDNSChangeAck{})
	command["allOf"] = []any{map[string]any{"if": map[string]any{"properties": map[string]any{"name": map[string]any{"const": "runtime.reload"}}}, "then": map[string]any{"properties": map[string]any{"args": Schema(RuntimeReloadArgs{})}}}}
	variants := []any{}
	for _, name := range MasterMessageTypes {
		data := types[name]
		envelope := Schema(Message{})
		p := envelope["properties"].(map[string]any)
		p["v"] = map[string]any{"const": Version}
		p["type"] = map[string]any{"const": name}
		p["data"] = data
		envelope["required"] = []string{"v", "type", "data"}
		variants = append(variants, envelope)
	}
	messages := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "title": "X-Node master messages", "oneOf": variants}
	return map[string]any{"config": root, "master_message": messages}
}

var MasterMessageTypes = []string{"ddns.changes.ack", "firewall.events.ack", "state.sync", "config.apply", "users.sync", "users.delta", "user.controls", "traffic.ack", "command", "command.cancel"}
var CommandNames = []string{"firewall.protected.sync", "firewall.geoip.sync", "firewall.bans.sync", "firewall.bans.update", "firewall.bans.get", "connections.list", "connections.close", "users.active_ips", "ips.control", "metrics.get", "jobs.list", "firewall.status", "firewall.confirm", "firewall.apply", "speedtest", "update.check", "update.status", "update.install", "update.rollback", "runtime.reload", "geodata.refresh", "ddns.run", "certificates.get", "traffic.flush", "config.validate"}
