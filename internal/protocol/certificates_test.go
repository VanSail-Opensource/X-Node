package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCertificateLifecycleContractRejectsInvalidActionsAndKeepsRevisionExact(t *testing.T) {
	for _, args := range []CertificateRunArgs{{ProfileID: "tls", Action: "delete", ExpectedRevision: 1}, {ProfileID: "tls", Action: "issue"}, {ProfileID: "../private", Action: "renew", ExpectedRevision: 1}} {
		if args.Validate() == nil {
			t.Fatal("invalid certificate lifecycle request accepted", args)
		}
	}
	if (CertificateRunArgs{ProfileID: "tls", Action: "renew", ExpectedRevision: 1}).Validate() != nil || CommandTimeout(CertificateRunCommand) != 5*time.Minute || ClassifyAction(CertificateRunCommand) != UtilityAction {
		t.Fatal("certificate command contract incomplete")
	}
	raw, err := json.Marshal(CertificateStatus{Revision: 9007199254740993})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	if fields["revision"] != "9007199254740993" {
		t.Fatal("large certificate revision rounded", string(raw))
	}
}
