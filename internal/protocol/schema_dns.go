package protocol

import "reflect"

func dnsPolicySchema(t reflect.Type, schema map[string]any) map[string]any {
	if t != reflect.TypeOf(DNSPolicy{}) {
		return schema
	}
	properties := schema["properties"].(map[string]any)
	mode := properties["mode"].(map[string]any)
	mode["deprecated"] = true
	mode["description"] = "Deprecated compatibility input. Empty/xray/smartdns are accepted; effective DNS always uses Xray. Legacy loopback behavior is migrated to native dns.servers."
	mode["enum"] = []string{"", "xray", "smartdns"}
	upstreams := properties["upstreams"].(map[string]any)
	upstreams["deprecated"] = true
	upstreams["description"] = "Ignored compatibility input. Configure upstream resolvers through native Xray dns.servers."
	return schema
}
