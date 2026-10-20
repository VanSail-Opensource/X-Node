package xray

import (
	"encoding/json"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

// One immutable client candidate bounds credentials/configuration retention.
// Every caller still receives a separate core instance and lifetime.
var clientPrepared struct {
	sync.Mutex
	key    [32]byte
	config *core.Config
}

func prepareClient(root map[string]any) (*core.Config, error) {
	material, err := listenerIdentity(root)
	if err != nil {
		return nil, err
	}
	key := sectionKey(material)
	clientPrepared.Lock()
	defer clientPrepared.Unlock()
	if clientPrepared.config == nil || clientPrepared.key != key {
		raw, err := json.Marshal(root)
		if err != nil {
			return nil, err
		}
		var c conf.Config
		if err = json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		built, err := c.Build()
		if err != nil {
			return nil, err
		}
		clientPrepared.key, clientPrepared.config = key, built
	}
	return proto.Clone(clientPrepared.config).(*core.Config), nil
}
