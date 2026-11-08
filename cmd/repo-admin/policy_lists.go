package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func decimalID(id int64) string { return strconv.FormatInt(id, 10) }

func listPolicies[T any](ctx context.Context, c *apiClient, path, key string) ([]T, error) {
	all := []T{}
	inspectedBytes := 0
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	for page := 1; page <= 100; page++ {
		var raw json.RawMessage
		if err := c.request(ctx, "GET", path+separator+"per_page=100&page="+strconv.Itoa(page), nil, &raw); err != nil {
			return nil, err
		}
		inspectedBytes += len(raw)
		if inspectedBytes > maxAPIBytes {
			return nil, errors.New("GitHub policy inventory exceeds inspection limit")
		}
		var entries []T
		var total *int
		if key != "" {
			var wrapper map[string]json.RawMessage
			if json.Unmarshal(raw, &wrapper) != nil || !bytes.HasPrefix(bytes.TrimSpace(wrapper[key]), []byte("[")) || json.Unmarshal(wrapper[key], &entries) != nil || json.Unmarshal(wrapper["total_count"], &total) != nil || total == nil {
				return nil, errors.New("invalid GitHub policy list")
			}
		} else if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) || json.Unmarshal(raw, &entries) != nil {
			return nil, errors.New("invalid GitHub policy list")
		}
		if len(entries) > 100 {
			return nil, errors.New("invalid GitHub policy page")
		}
		all = append(all, entries...)
		if len(entries) < 100 {
			if total != nil && *total != len(all) {
				return nil, errors.New("GitHub policy list changed during inspection")
			}
			return all, nil
		}
	}
	return nil, errors.New("GitHub policy list exceeds inspection limit")
}
