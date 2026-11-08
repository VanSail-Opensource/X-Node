package agent

import (
	"errors"
	"io"
	"testing"
)

type jobErrorWithBytes struct{ read bool }

func (r *jobErrorWithBytes) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	return copy(p, "[]"), errors.New("constructed final read error")
}

func TestLegacyRecoveryRejectsErrorReturnedWithCompleteBytes(t *testing.T) {
	if results, err := readLegacyJobMetadata(&jobErrorWithBytes{}); err == nil || results != nil {
		t.Fatal("I/O uncertainty was mistaken for complete history")
	}
}
