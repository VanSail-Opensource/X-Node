package releases

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"runtime"
)

type BinaryMetadata struct {
	SHA256   string `json:"sha256"`
	Platform string `json:"platform"`
}

// ExecutableMetadata hashes the current binary using bounded streaming memory.
func ExecutableMetadata() (BinaryMetadata, error) {
	path, err := os.Executable()
	if err != nil {
		return BinaryMetadata{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return BinaryMetadata{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return BinaryMetadata{}, err
	}
	return BinaryMetadata{SHA256: hex.EncodeToString(hash.Sum(nil)), Platform: runtime.GOOS + "-" + runtime.GOARCH}, nil
}
