package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"aead.dev/minisign"
)

func TestKeyGenerationProtectsExistingAndAliasedPaths(t *testing.T) {
	for _, kind := range []string{"missing public", "same path", "existing public", "private symlink", "public symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			key, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
			owned := filepath.Join(dir, "existing")
			if err := os.WriteFile(owned, []byte("preserved"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing public":
				public = ""
			case "same path":
				public = key
			case "existing public":
				public = owned
			case "private symlink":
				if err := os.Symlink(owned, key); err != nil {
					t.Fatal(err)
				}
			case "public symlink":
				if err := os.Symlink(owned, public); err != nil {
					t.Fatal(err)
				}
			}
			if generateKeyPair(key, public) == nil {
				t.Fatal("unsafe key destination accepted")
			}
			if raw, err := os.ReadFile(owned); err != nil || string(raw) != "preserved" {
				t.Fatal("key generation changed caller-owned file", err)
			}
			if kind != "private symlink" {
				if _, err := os.Stat(key); !os.IsNotExist(err) {
					t.Fatal("invalid outputs published a new private key", err)
				}
			}
		})
	}
}

func TestKeyFilePublicationIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	var winners atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Go(func() {
			if writeNewKeyFile(path, []byte("key evidence"), 0600) == nil {
				winners.Add(1)
			}
		})
	}
	workers.Wait()
	if winners.Load() != 1 {
		t.Fatal("concurrent writers replaced a key", winners.Load())
	}
}

func TestNewKeyPairHasMatchingPublicKeyAndPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	key, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := generateKeyPair(key, public); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	var private minisign.PrivateKey
	if err := private.UnmarshalText(raw); err != nil {
		t.Fatal("generated private key is not readable")
	}
	raw, err = os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	var pub minisign.PublicKey
	if err := pub.UnmarshalText(raw); err != nil || !pub.Equal(private.Public()) {
		t.Fatal("generated key pair does not match")
	}
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private key permissions are not restricted", err)
	}
}
