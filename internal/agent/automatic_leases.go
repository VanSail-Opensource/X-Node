package agent

import (
	"context"
	"encoding/json"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

func (a *Agent) automaticLeaseCommand(ctx context.Context, args json.RawMessage) (any, error) {
	var update protocol.AutomaticLeaseUpdate
	if err := protocol.Decode(args, &update); err != nil {
		return nil, err
	}
	return a.Guard.GrantAutomatic(ctx, update)
}
