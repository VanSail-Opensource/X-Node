package xray

import "testing"

func TestRealityLogObservation(t *testing.T) {
	const prefix = "transport/internet/tcp: REALITY: processed invalid connection from "
	for _, test := range []struct {
		name, text, ip, rule string
	}{
		{"probe", prefix + "8.8.8.8:443: failed to read client hello", "8.8.8.8", "xray_tcp_probe"},
		{"auth v6", prefix + "[2001:4860::1]:123: authentication failed or validation criteria not met", "2001:4860::1", "xray_auth_failure"},
		{"server name", prefix + "8.8.8.8:443: server name mismatch: example.net", "8.8.8.8", "xray_invalid"},
		{"target failure", prefix + "8.8.8.8:443: target sent incorrect server hello or handshake incomplete", "", ""},
		{"ambiguous", prefix + "8.8.8.8:443: handshake did not complete successfully", "", ""},
		{"forged source", "other: " + prefix + "8.8.8.8:443: failed to read client hello", "", ""},
		{"invalid remote", prefix + "not-an-address: failed to read client hello", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, ok := RealityLogObservation(test.text)
			if ok != (test.rule != "") || ok && (value.IP.String() != test.ip || value.Rule != test.rule) {
				t.Fatalf("observation = %+v, %t", value, ok)
			}
		})
	}
}
