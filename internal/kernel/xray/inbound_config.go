package xray

import (
	"github.com/xtls/xray-core/common/serial"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
)

// InboundConfig carries native public configuration without inspecting the
// private core registry. Its descriptor is maintained with integration.proto.
type InboundConfig struct {
	state         protoimpl.MessageState
	NativeType    string `protobuf:"bytes,1,opt,name=native_type,json=nativeType,proto3" json:"native_type,omitempty"`
	NativeValue   []byte `protobuf:"bytes,2,opt,name=native_value,json=nativeValue,proto3" json:"native_value,omitempty"`
	Tag           string `protobuf:"bytes,3,opt,name=tag,proto3" json:"tag,omitempty"`
	Reality       bool   `protobuf:"varint,4,opt,name=reality,proto3" json:"reality,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InboundConfig) Reset() {
	*x = InboundConfig{}
	protoimpl.X.MessageStateOf(protoimpl.Pointer(x)).StoreMessageInfo(&integrationMessages[1])
}
func (x *InboundConfig) String() string { return protoimpl.X.MessageStringOf(x) }
func (*InboundConfig) ProtoMessage()    {}
func (x *InboundConfig) ProtoReflect() protoreflect.Message {
	mi := &integrationMessages[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}
func (x *InboundConfig) native() *serial.TypedMessage {
	return &serial.TypedMessage{Type: x.NativeType, Value: x.NativeValue}
}
