// Runtime protobuf descriptor for the public integration.proto configuration.
package xray

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/runtime/protoimpl"
	"google.golang.org/protobuf/types/descriptorpb"
	"reflect"
	"sync"
)

type ManagerConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ManagerConfig) Reset() {
	*x = ManagerConfig{}
	mi := &integrationMessages[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}
func (x *ManagerConfig) String() string { return protoimpl.X.MessageStringOf(x) }
func (*ManagerConfig) ProtoMessage()    {}
func (x *ManagerConfig) ProtoReflect() protoreflect.Message {
	mi := &integrationMessages[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}
func (*ManagerConfig) Descriptor() ([]byte, []int) {
	integrationOnce.Do(func() { integrationRaw = protoimpl.X.CompressGZIP(integrationRaw) })
	return integrationRaw, []int{0}
}

type DNSConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
	NativeValue   []byte `protobuf:"bytes,1,opt,name=native_value,json=nativeValue,proto3" json:"native_value,omitempty"`
	UseLocal      bool   `protobuf:"varint,2,opt,name=use_local,json=useLocal,proto3" json:"use_local,omitempty"`
}

func (x *DNSConfig) Reset() {
	*x = DNSConfig{}
	mi := &integrationMessages[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}
func (x *DNSConfig) String() string { return protoimpl.X.MessageStringOf(x) }
func (*DNSConfig) ProtoMessage()    {}
func (x *DNSConfig) ProtoReflect() protoreflect.Message {
	mi := &integrationMessages[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}
func (*DNSConfig) Descriptor() ([]byte, []int) {
	integrationOnce.Do(func() { integrationRaw = protoimpl.X.CompressGZIP(integrationRaw) })
	return integrationRaw, []int{2}
}

type PolicyConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
	NativeValue   []byte `protobuf:"bytes,1,opt,name=native_value,json=nativeValue,proto3" json:"native_value,omitempty"`
}

func (x *PolicyConfig) Reset() {
	*x = PolicyConfig{}
	mi := &integrationMessages[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}
func (x *PolicyConfig) String() string { return protoimpl.X.MessageStringOf(x) }
func (*PolicyConfig) ProtoMessage()    {}
func (x *PolicyConfig) ProtoReflect() protoreflect.Message {
	mi := &integrationMessages[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}
func (*PolicyConfig) Descriptor() ([]byte, []int) {
	integrationOnce.Do(func() { integrationRaw = protoimpl.X.CompressGZIP(integrationRaw) })
	return integrationRaw, []int{3}
}

type RouterConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
	NativeValue   []byte `protobuf:"bytes,1,opt,name=native_value,json=nativeValue,proto3" json:"native_value,omitempty"`
}

func (x *RouterConfig) Reset() {
	*x = RouterConfig{}
	mi := &integrationMessages[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}
func (x *RouterConfig) String() string { return protoimpl.X.MessageStringOf(x) }
func (*RouterConfig) ProtoMessage()    {}
func (x *RouterConfig) ProtoReflect() protoreflect.Message {
	mi := &integrationMessages[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}
func (*RouterConfig) Descriptor() ([]byte, []int) {
	integrationOnce.Do(func() { integrationRaw = protoimpl.X.CompressGZIP(integrationRaw) })
	return integrationRaw, []int{4}
}

var FileIntegration protoreflect.FileDescriptor
var integrationMessages = make([]protoimpl.MessageInfo, 5)
var integrationOnce sync.Once
var integrationRaw []byte

func init() {
	name, pkg, syntax, message, option := "integration.proto", "xnode.integration", "proto3", "ManagerConfig", "github.com/VanSail-Opensource/X-Node/internal/kernel/xray"
	inbound := &descriptorpb.DescriptorProto{Name: proto.String("InboundConfig"), Field: []*descriptorpb.FieldDescriptorProto{
		{Name: proto.String("native_type"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
		{Name: proto.String("native_value"), Number: proto.Int32(2), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()},
		{Name: proto.String("tag"), Number: proto.Int32(3), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()},
		{Name: proto.String("reality"), Number: proto.Int32(4), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum()},
	}}
	valueMessage := func(name string) *descriptorpb.DescriptorProto {
		return &descriptorpb.DescriptorProto{Name: &name, Field: []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("native_value"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum()},
		}}
	}
	dns := valueMessage("DNSConfig")
	dns.Field = append(dns.Field, &descriptorpb.FieldDescriptorProto{Name: proto.String("use_local"), Number: proto.Int32(2), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum()})
	integrationRaw, _ = proto.Marshal(&descriptorpb.FileDescriptorProto{Name: &name, Package: &pkg, Syntax: &syntax, Options: &descriptorpb.FileOptions{GoPackage: &option}, MessageType: []*descriptorpb.DescriptorProto{{Name: &message}, inbound, dns, valueMessage("PolicyConfig"), valueMessage("RouterConfig")}})
	type marker struct{}
	out := protoimpl.TypeBuilder{File: protoimpl.DescBuilder{GoPackagePath: reflect.TypeOf(marker{}).PkgPath(), RawDescriptor: integrationRaw, NumMessages: 5}, GoTypes: []any{(*ManagerConfig)(nil), (*InboundConfig)(nil), (*DNSConfig)(nil), (*PolicyConfig)(nil), (*RouterConfig)(nil)}, MessageInfos: integrationMessages}.Build()
	FileIntegration = out.File
}
