package xray

import (
	"fmt"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func memoryUsers(cfg *core.InboundHandlerConfig) ([]*protocol.MemoryUser, error) {
	msg, err := cfg.ProxySettings.GetInstance()
	if err != nil {
		return nil, err
	}
	if wrapped, ok := msg.(*InboundConfig); ok {
		msg, err = wrapped.native().GetInstance()
		if err != nil {
			return nil, err
		}
	}
	var out []*protocol.MemoryUser
	var failure error
	var walk func(protoreflect.Message)
	walk = func(m protoreflect.Message) {
		if u, ok := m.Interface().(*protocol.User); ok {
			memory, err := u.ToMemoryUser()
			if err != nil {
				failure = err
			} else {
				out = append(out, memory)
			}
			return
		}
		m.Range(func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if f.IsList() && f.Kind() == protoreflect.MessageKind {
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					walk(list.Get(i).Message())
				}
			} else if !f.IsMap() && f.Kind() == protoreflect.MessageKind {
				walk(v.Message())
			}
			return true
		})
	}
	walk(msg.ProtoReflect())
	if failure != nil {
		return nil, fmt.Errorf("invalid memory account")
	}
	return out, nil
}
