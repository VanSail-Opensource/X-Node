package protocol

import (
	"strings"
	"testing"
)

func TestDDNSRecordNamesCoverOwnedDNSNames(t *testing.T) {
	for _, test := range []struct{ zone, name, wantZone, wantName string }{
		{"Example.COM.", "@", "example.com.", "example.com"},
		{"example.com", "EXAMPLE.COM.", "example.com.", "example.com"},
		{"example.com", "node.example.com", "example.com.", "node.example.com"},
		{"example.com", "*.example.com", "example.com.", "*.example.com"},
		{"example.com", "_service.-owner-.example.com", "example.com.", "_service.-owner-.example.com"},
		{"BÜCHER.Example", "www.bücher.example.", "xn--bcher-kva.example.", "www.xn--bcher-kva.example"},
		{"example\u3002com\uff0e", "node\uff61example.com", "example.com.", "node.example.com"},
	} {
		zone, name, err := DDNSRecordNames(test.zone, test.name)
		if err != nil || zone != test.wantZone || name != test.wantName {
			t.Fatal("valid owned DNS name was changed or rejected", test, zone, name, err)
		}
	}
}

func TestDDNSRecordNamesRejectOutOfZoneOrMalformedInputs(t *testing.T) {
	for _, test := range [][2]string{
		{"example.com", "node"}, {"example.com", "otherexample.com"},
		{"example.com", "example.com.evil.invalid"}, {"example.com", ""},
		{"", "node.example.com"}, {"*.example.com", "node.example.com"},
		{"example.com", "https://node.example.com"}, {"example.com", "a..example.com"},
		{"example.com", "a.\nexample.com"}, {"example.com", " example.com"},
		{"example.com", "example.com.."}, {"example.com", "a.*.example.com"},
		{"example.com", "a*.example.com"}, {"example.com", "_bücher.example.com"},
		{"example.com", strings.Repeat("x", 64) + ".example.com"},
		{"example.com", strings.Repeat(strings.Repeat("x", 63)+".", 4) + "example.com"},
	} {
		if _, _, err := DDNSRecordNames(test[0], test[1]); err == nil {
			t.Fatal("invalid DNS name or ownership boundary accepted", test)
		}
	}
}

func TestDDNSInputsAreValidatedBeforeScheduling(t *testing.T) {
	valid := DDNSJob{ID: "wan", Provider: "cloud", Zone: "example.com", Name: "@", IPv4: "192.0.2.1"}
	for name, mutate := range map[string]func(*DDNSJob){
		"missing sources":        func(j *DDNSJob) { j.IPv4 = "" },
		"auto without discovery": func(j *DDNSJob) { j.IPv4 = "auto" },
		"wrong IPv4 family":      func(j *DDNSJob) { j.IPv4 = "2001:db8::1" },
		"wrong IPv6 family":      func(j *DDNSJob) { j.IPv6 = "::ffff:192.0.2.1" },
		"loopback":               func(j *DDNSJob) { j.IPv4 = "127.0.0.1" },
		"multicast":              func(j *DDNSJob) { j.IPv6 = "ff02::1" },
		"zone scope":             func(j *DDNSJob) { j.IPv6 = "2001:db8::1%eth0" },
		"insecure lookup":        func(j *DDNSJob) { j.IPv4URL = "http://lookup.example/ip" },
		"lookup credentials":     func(j *DDNSJob) { j.IPv4URL = "https://user:secret@lookup.example/ip" },
		"interface whitespace":   func(j *DDNSJob) { j.Interface = "eth 0" },
		"interface path":         func(j *DDNSJob) { j.Interface = "../eth0" },
		"TTL overflow":           func(j *DDNSJob) { j.TTLSeconds = MaxDDNSTTLSeconds + 1 },
		"negative TTL":           func(j *DDNSJob) { j.TTLSeconds = -1 },
		"excess interval":        func(j *DDNSJob) { j.IntervalSeconds = 86401 },
	} {
		t.Run(name, func(t *testing.T) {
			job := valid
			mutate(&job)
			if err := job.Validate(); err == nil {
				t.Fatal("invalid background job admitted", job)
			}
		})
	}
	for _, source := range []string{"192.0.2.1", "::ffff:192.0.2.1", "auto"} {
		job := valid
		job.IPv4, job.IPv4URL, job.TTLSeconds = source, "https://lookup.example/ip", MaxDDNSTTLSeconds
		if err := job.Validate(); err != nil {
			t.Fatal("valid bounded job rejected", err)
		}
	}
}
