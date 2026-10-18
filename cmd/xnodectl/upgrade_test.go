package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type installedMetadata struct{}

func (installedMetadata) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "/usr/local/bin/x-node" || len(args) != 1 || args[0] != "--version" {
		panic("upgrade invoked the obsolete installed CLI")
	}
	return []byte(`{"version":"v2.0.2"}`), nil
}

type releaseMetadata struct{}

func (releaseMetadata) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"tag_name":"v2.0.7","draft":false,"prerelease":false}`))}, nil
}

func TestStagedCLIUpgradesTheInstalledAgentInsteadOfComparingItself(t *testing.T) {
	manager, err := installedUpdater(context.Background(), installedMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	manager.Client = &http.Client{Transport: releaseMetadata{}}
	release, err := manager.Check(context.Background(), "v2.0.7")
	if err != nil || !release.Available || release.Current != "v2.0.2" || release.Version != "v2.0.7" {
		t.Fatal("staged CLI skipped replacement of the older agent/CLI pair", err, release)
	}
}
