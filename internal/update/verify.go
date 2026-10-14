// Package update verifies signed release manifests before executing staged binaries.
package update

import (
	"aead.dev/minisign"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed release.pub
var publicKeyText []byte
var stableVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

func PublicKey() ([]byte, error) {
	var key minisign.PublicKey
	if e := key.UnmarshalText(publicKeyText); e != nil {
		return nil, errors.New("release trust key is not configured")
	}
	return append([]byte(nil), publicKeyText...), nil
}
func Verify(manifest, signature []byte, version string) (map[string]string, error) {
	return VerifyWithKey(publicKeyText, manifest, signature, version)
}
func VerifyWithKey(keyText, manifest, signature []byte, version string) (map[string]string, error) {
	var key minisign.PublicKey
	if e := key.UnmarshalText(keyText); e != nil {
		return nil, errors.New("invalid release trust key")
	}
	if !stableVersion.MatchString(version) || len(manifest) > 1<<20 || len(signature) > 4096 || !minisign.Verify(key, manifest, signature) {
		return nil, errors.New("release signature verification failed")
	}
	var sig minisign.Signature
	if sig.UnmarshalText(signature) != nil || sig.TrustedComment != "version:"+version {
		return nil, errors.New("signed release version differs")
	}
	entries := map[string]string{}
	for _, line := range strings.Split(string(manifest), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 || len(parts[0]) != 64 || filepath.Base(parts[1]) != parts[1] || strings.ContainsAny(parts[1], "/\\") || entries[parts[1]] != "" {
			return nil, errors.New("invalid SHA256SUMS")
		}
		hash, e := hex.DecodeString(parts[0])
		if e != nil || len(hash) != 32 {
			return nil, errors.New("invalid SHA-256")
		}
		entries[parts[1]] = strings.ToLower(parts[0])
	}
	if len(entries) == 0 {
		return nil, errors.New("empty signed manifest")
	}
	return entries, nil
}
func VerifyFile(path, hash string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	actual := sha256.Sum256(b)
	if hex.EncodeToString(actual[:]) != hash {
		return errors.New("binary SHA-256 mismatch")
	}
	return nil
}
