package main

import (
	"errors"
	"os"
	"path/filepath"

	"aead.dev/minisign"
	"github.com/VanSail-Opensource/X-Node/internal/state"
)

func generateKeyPair(keyPath, publicPath string) error {
	if keyPath == "" || publicPath == "" {
		return errors.New("key-file and public-out are required")
	}
	privateName, err := filepath.Abs(keyPath)
	if err != nil {
		return err
	}
	publicName, err := filepath.Abs(publicPath)
	if err != nil {
		return err
	}
	if privateName == publicName {
		return errors.New("private and public key outputs must differ")
	}
	for _, path := range []string{keyPath, publicPath} {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("key output already exists")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	public, private, err := minisign.GenerateKey(nil)
	if err != nil {
		return err
	}
	secret, err := private.MarshalText()
	if err != nil {
		return err
	}
	pub, err := public.MarshalText()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		return err
	}
	if err = writeNewKeyFile(keyPath, secret, 0600); err != nil {
		return err
	}
	return writeNewKeyFile(publicPath, pub, 0644)
}

func writeNewKeyFile(path string, data []byte, mode os.FileMode) error {
	// O_EXCL protects both existing keys and symlinks, including a destination
	// created after the preflight. Failed publication keeps new recovery evidence.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	err = errors.Join(writeErr, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	return state.SyncDirectory(filepath.Dir(path))
}
