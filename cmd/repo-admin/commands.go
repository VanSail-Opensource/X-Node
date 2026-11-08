package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

var stableVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func execute(ctx context.Context, api *apiClient, operation string, opts options, out io.Writer) error {
	switch operation {
	case "protect", "protect-release":
		if err := api.protectRelease(ctx); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Repository release protections verified.")
		return err
	case "signing-secret":
		if err := api.signingSecret(ctx, opts.keyFile); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Protected release signing secret configured.")
		return err
	case "dispatch-release":
		if !stableVersion.MatchString(opts.version) || opts.runID <= 0 {
			return errors.New("version and positive Quality run-id are required")
		}
		if err := api.verifyRelease(ctx); err != nil {
			return err
		}
		body := map[string]any{"ref": "main", "inputs": map[string]string{"version": opts.version, "quality_run_id": strconv.FormatInt(opts.runID, 10)}}
		if err := api.request(ctx, "POST", repositoryRoot+"/actions/workflows/release.yml/dispatches", body, nil); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Release workflow dispatched from main.")
		return err
	case "automerge":
		if err := api.request(ctx, "PATCH", repositoryRoot, map[string]bool{"allow_auto_merge": true}, nil); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, "Repository auto-merge enabled.")
		return err
	default:
		return api.observe(ctx, operation, opts, out)
	}
}

func (c *apiClient) protectRelease(ctx context.Context) error {
	if err := c.protectMain(ctx); err != nil {
		return fmt.Errorf("main branch protection: %w", err)
	}
	if err := c.protectEnvironment(ctx); err != nil {
		return fmt.Errorf("release environment protection: %w", err)
	}
	if err := c.protectTags(ctx); err != nil {
		return fmt.Errorf("release tag protection: %w", err)
	}
	return c.verifyRelease(ctx)
}

func (c *apiClient) verifyRelease(ctx context.Context) error {
	if err := c.verifyMain(ctx); err != nil {
		return fmt.Errorf("main branch protection: %w", err)
	}
	if err := c.verifyEnvironment(ctx, nil); err != nil {
		return fmt.Errorf("release environment protection: %w", err)
	}
	if err := c.verifyTags(ctx); err != nil {
		return fmt.Errorf("release tag protection: %w", err)
	}
	return nil
}
