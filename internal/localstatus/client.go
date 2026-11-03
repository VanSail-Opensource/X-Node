package localstatus

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

func Query(ctx context.Context, path string) (Snapshot, error) {
	var out Snapshot
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(child, "unix", path)
	if err != nil {
		return out, errors.New("agent status is not available")
	}
	defer connection.Close()
	deadline, _ := child.Deadline()
	_ = connection.SetReadDeadline(deadline)
	data, err := io.ReadAll(io.LimitReader(connection, 4097))
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &out) != nil {
		return out, errors.New("invalid agent status response")
	}
	return out, nil
}
