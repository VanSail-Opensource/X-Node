package update

import (
	"aead.dev/minisign"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSignatureHashAndVersionBinding(t *testing.T) {
	public, private, e := minisign.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := public.MarshalText()
	hash := sha256.Sum256([]byte("binary"))
	manifest := []byte(hex.EncodeToString(hash[:]) + "  x-node-linux-amd64\n")
	signature := minisign.SignWithComments(private, manifest, "version:v1.2.3", "release")
	if _, e = VerifyWithKey(key, manifest, signature, "v1.2.3"); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyWithKey(key, append(manifest, 'x'), signature, "v1.2.3"); e == nil {
		t.Fatal("tampered manifest accepted")
	}
	if _, e = VerifyWithKey(key, manifest, signature, "v1.2.4"); e == nil {
		t.Fatal("relabelled old release accepted")
	}
	if _, e = VerifyWithKey(key, manifest, nil, "v1.2.3"); e == nil {
		t.Fatal("unsigned release accepted")
	}
}
