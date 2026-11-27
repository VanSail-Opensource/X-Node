package state

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
)

// The top-level authorization has always been authoritative for startup,
// including for older agents. Omit only exact duplicate credential lists.
// Keep older accepted users when they differ from current authorization.
type diskState struct {
	Data
	SharedConfigUsers  bool `json:"shared_config_users,omitempty"`
	SharedDesiredUsers bool `json:"shared_desired_users,omitempty"`
}

func encodeState(data Data) ([]byte, error) {
	disk := diskState{Data: data}
	compact := func(config *protocol.Config) (*protocol.Config, bool) {
		if config == nil || len(data.Users) == 0 || !reflect.DeepEqual(config.Users, data.Users) {
			return config, false
		}
		copy := *config
		copy.Users = nil
		return &copy, true
	}
	disk.Config, disk.SharedConfigUsers = compact(data.Config)
	disk.DesiredConfig, disk.SharedDesiredUsers = compact(data.DesiredConfig)
	return json.Marshal(disk)
}

func decodeState(raw []byte, data *Data) error {
	var disk diskState
	if err := json.Unmarshal(raw, &disk); err != nil {
		return err
	}
	restore := func(config *protocol.Config, shared bool) error {
		if !shared {
			return nil
		}
		if config == nil || config.Users != nil || len(disk.Users) == 0 {
			return errors.New("invalid shared authorization snapshot")
		}
		config.Users = disk.Users
		return nil
	}
	if err := restore(disk.Config, disk.SharedConfigUsers); err != nil {
		return err
	}
	if err := restore(disk.DesiredConfig, disk.SharedDesiredUsers); err != nil {
		return err
	}
	*data = disk.Data
	return nil
}
