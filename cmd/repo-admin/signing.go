package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"

	"golang.org/x/crypto/nacl/box"
)

// Rotating a key never creates an environment or weakens any protection policy.
func (c *apiClient) signingSecret(ctx context.Context, keyPath string) error {
	if keyPath == "" {
		return errors.New("key-file is required")
	}
	if err := c.verifyRelease(ctx); err != nil {
		return err
	}
	secret, err := os.ReadFile(keyPath)
	if err != nil || len(secret) == 0 {
		return errors.New("signing key unavailable")
	}
	var public struct {
		KeyID string `json:"key_id"`
		Key   string `json:"key"`
	}
	if err := c.request(ctx, "GET", environmentPath+"/secrets/public-key", nil, &public); err != nil {
		return err
	}
	decoded, err := base64.StdEncoding.DecodeString(public.Key)
	if err != nil || len(decoded) != 32 || public.KeyID == "" {
		return errors.New("invalid repository encryption key")
	}
	var recipient [32]byte
	copy(recipient[:], decoded)
	encrypted, err := box.SealAnonymous(nil, secret, &recipient, rand.Reader)
	if err != nil {
		return errors.New("signing key encryption failed")
	}
	body := map[string]string{"key_id": public.KeyID, "encrypted_value": base64.StdEncoding.EncodeToString(encrypted)}
	if err := c.request(ctx, "PUT", environmentPath+"/secrets/RELEASE_MINISIGN_SECRET_KEY", body, nil); err != nil {
		return err
	}
	err = c.request(ctx, "DELETE", repositoryRoot+"/actions/secrets/RELEASE_MINISIGN_SECRET_KEY", nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}
