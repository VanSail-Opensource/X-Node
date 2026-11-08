package host

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUtilitiesDoNotInheritProcessEnvironmentOrPath(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux host contract")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "env"), []byte("#!/bin/sh\necho compromised\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("LD_PRELOAD", "/untrusted.so")
	t.Setenv("PYTHONPATH", "/untrusted")
	t.Setenv("HOST_UNTRUSTED_MARKER", "secret")
	out, err := (Commands{}).Run(context.Background(), "env")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(got) != 3 {
		t.Fatalf("unexpected inherited environment: %q", got)
	}
	for _, value := range got {
		if value != "PATH="+systemPath && value != "LANG=C" && value != "LC_ALL=C" {
			t.Fatal("utility inherited an untrusted variable")
		}
	}
	if _, err := utilityCommand(context.Background(), "relative/env"); err == nil {
		t.Fatal("accepted relative executable path")
	}
}
