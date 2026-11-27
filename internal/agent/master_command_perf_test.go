package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIndexedCommandReceiptsFollowEviction(t *testing.T) {
	j := &Jobs{}
	for i := 0; i <= maxJobHistory; i++ {
		j.finishVolatile(boundedJobResult(JobResult{ID: fmt.Sprint(i), Command: "metrics.get", Status: "completed"}))
	}
	if _, ok := j.receipt("0"); ok {
		t.Fatal("evicted receipt remains indexed")
	}
	for i := 1; i <= maxJobHistory; i++ {
		id := fmt.Sprint(i)
		if result, ok := j.receipt(id); !ok || result.ID != id {
			t.Fatalf("missing or incorrect receipt %s", id)
		}
	}
}

func TestJobStartupKeepsAlreadyCanonicalPrivateJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	want := boundedJobResult(JobResult{ID: "previous-command", Command: "update.install", Status: "completed"})
	original, err := encodeJobHistory([]JobResult{want})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	j := &Jobs{path: path, write: func(string, []byte, os.FileMode) error { return errors.New("unexpected disk write") }}
	if err := j.loadHistory(); err != nil {
		t.Fatal(err)
	}
	if got, ok := j.receipt(want.ID); !ok || got.Status != want.Status {
		t.Fatal("skipping the rewrite lost the durable receipt")
	}
}
