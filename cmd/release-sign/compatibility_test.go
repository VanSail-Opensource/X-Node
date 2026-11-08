package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
	"github.com/VanSail-Opensource/X-Node/internal/update"
)

func TestDistributionMinisignAcceptsExistingKeyFormatAndAgentVerifiesIt(t *testing.T) {
	tool, err := exec.LookPath("minisign")
	if err != nil {
		t.Skip("hosted Quality installs the distribution minisign utility")
	}
	dir := t.TempDir()
	public, private, err := minisign.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := private.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	key, manifest, signature := filepath.Join(dir, "key"), filepath.Join(dir, "SHA256SUMS"), filepath.Join(dir, "SHA256SUMS.minisig")
	data := []byte(strings.Repeat("0", 64) + "  x-node-linux-amd64\n")
	for path, value := range map[string][]byte{key: secret, manifest: data} {
		if err := os.WriteFile(path, value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, tool, args...)
		command.Env, command.Dir = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}, dir
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("distribution minisign failed: %v: %s", err, output)
		}
	}
	run("-S", "-s", key, "-m", manifest, "-x", signature, "-t", "version:v9.9.9", "-c", "X-Node release", "-q")
	signed, err := os.ReadFile(signature)
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := public.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := update.VerifyWithKey(publicText, data, signed, "v9.9.9"); err != nil {
		t.Fatal("agent rejected distribution signature", err)
	}
	if _, err := update.VerifyWithKey(publicText, data, signed, "v9.9.8"); err == nil {
		t.Fatal("signature accepted for another release version")
	}
	reader := minisign.NewReader(bytes.NewReader(data))
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signature, reader.SignWithComments(private, "version:v9.9.9", "X-Node release"), 0600); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(publicText)), "\n")
	run("-V", "-H", "-P", lines[len(lines)-1], "-m", manifest, "-x", signature, "-q")
}
