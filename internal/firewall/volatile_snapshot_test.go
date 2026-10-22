package firewall

import (
	"strings"
	"testing"
)

func TestRollbackSnapshotExcludesOnlyDerivedProtection(t *testing.T) {
	raw := []byte("table inet x_node {\n\tset trusted_v4 {\n\t\ttype ipv4_addr\n\t\tflags dynamic,timeout\n\t\telements = { 8.8.8.8 timeout 1h,\n\t\t\t9.9.9.9 timeout 2h }\n\t}\n\tset trusted_v6 {\n\t\ttype ipv6_addr\n\t\telements = { 2001:4860::1 timeout 1h }\n\t}\n\tset banned_v4_v2 {\n\t\telements = { 1.1.1.1 }\n\t}\n}\ntable inet user_owned {\n\tset trusted_v4 {\n\t\telements = { 8.8.4.4 }\n\t}\n}\n")
	result, err := withoutVolatileProtection(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"8.8.8.8", "9.9.9.9", "2001:4860::1"} {
		if strings.Contains(string(result), private) {
			t.Fatal("observed source persisted", private)
		}
	}
	for _, retained := range []string{"1.1.1.1", "8.8.4.4", "flags dynamic,timeout", "set trusted_v6"} {
		if !strings.Contains(string(result), retained) {
			t.Fatal("unrelated rules lost", retained)
		}
	}
	if !strings.Contains(string(raw), "8.8.8.8") {
		t.Fatal("input snapshot mutated")
	}
	if _, err = withoutVolatileProtection([]byte("table inet x_node {\n set trusted_v4 {\n elements = { 8.8.8.8\n")); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
}
