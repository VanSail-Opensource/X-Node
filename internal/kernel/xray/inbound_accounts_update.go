package xray

import (
	"context"
	"errors"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
)

type inboundAccountUpdate struct {
	manager proxy.UserManager
	remove  []*protocol.MemoryUser
	add     []*protocol.MemoryUser
}

func prepareAccounts(ctx context.Context, manager proxy.UserManager, config *core.InboundHandlerConfig) (inboundAccountUpdate, error) {
	result := inboundAccountUpdate{manager: manager}
	users, err := memoryUsers(config)
	if err != nil {
		return result, err
	}
	desired := make(map[string]*protocol.MemoryUser, len(users))
	for _, user := range users {
		desired[user.Email] = user
	}
	for _, live := range manager.GetUsers(ctx) {
		next := desired[live.Email]
		if next != nil && live.Level == next.Level && live.Account.Equals(next.Account) {
			delete(desired, live.Email)
			continue
		}
		result.remove = append(result.remove, live)
	}
	for _, user := range users {
		if desired[user.Email] != nil {
			result.add = append(result.add, user)
		}
	}
	return result, nil
}

// Keep native protocol replay state alive. Only changed credentials have their
// records edited. The registry remains authoritative throughout the operation.
func (p inboundAccountUpdate) apply(ctx context.Context) (func() error, error) {
	var removed, added []*protocol.MemoryUser
	undo := func() error {
		var result error
		for _, user := range added {
			result = errors.Join(result, p.manager.RemoveUser(ctx, user.Email))
		}
		for _, user := range removed {
			result = errors.Join(result, p.manager.AddUser(ctx, user))
		}
		return result
	}
	for _, user := range p.remove {
		if err := p.manager.RemoveUser(ctx, user.Email); err != nil {
			return undo, err
		}
		removed = append(removed, user)
	}
	for _, user := range p.add {
		if err := p.manager.AddUser(ctx, user); err != nil {
			return undo, err
		}
		added = append(added, user)
	}
	return undo, nil
}
