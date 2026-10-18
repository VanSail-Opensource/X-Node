package cert

import (
	"errors"
	"io"
	"os"
)

func readCertificateFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("certificate material exceeds one MiB")
	}
	return raw, nil
}
