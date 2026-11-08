// repo-admin inspects and configures repository policy without printing credentials.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	keyFile string
	runID   int64
	version string
}

func run() error {
	var opts options
	flag.StringVar(&opts.keyFile, "key-file", "", "private release key file")
	flag.Int64Var(&opts.runID, "run-id", 0, "Quality workflow run ID")
	flag.StringVar(&opts.version, "version", "", "stable release tag vX.Y.Z")
	flag.Parse()
	if flag.NArg() != 1 {
		return errors.New("choose info, runs, jobs, releases, workflow, protect-release, signing-secret, dispatch-release or automerge")
	}
	token, err := credentialToken()
	if err != nil {
		return err
	}
	return execute(context.Background(), newAPIClient(token), flag.Arg(0), opts, os.Stdout)
}

func credentialToken() (string, error) {
	cmd := exec.Command("git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	credential, err := cmd.Output()
	if err != nil {
		return "", errors.New("GitHub credentials unavailable")
	}
	for _, line := range strings.Split(string(credential), "\n") {
		key, value, _ := strings.Cut(line, "=")
		if key == "password" && value != "" {
			return value, nil
		}
	}
	return "", errors.New("GitHub token unavailable")
}
