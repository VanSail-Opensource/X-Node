package protocol

import (
	"encoding/json"
	wire "github.com/VanSail-Opensource/X-Node/internal/protocol"
	"time"
)

func New(kind, id string, revision uint64, data any) Message {
	return wire.New(kind, id, revision, data)
}

func Parse(raw []byte) (Message, error)      { return wire.Parse(raw) }
func Decode(raw []byte, target any) error    { return wire.Decode(raw, target) }
func ParseConfig(raw []byte) (Config, error) { return wire.ParseConfig(raw) }
func ValidateUsers(users []User) error       { return wire.ValidateUsers(users) }
func UserEmail(user User, tag string) string { return wire.UserEmail(user, tag) }

func TransitEmail(userID int, binding TransitCredential) string {
	return wire.TransitEmail(userID, binding)
}

func SourceGeoIPListeners(raw json.RawMessage) ([]SourceGeoIPListener, error) {
	return wire.SourceGeoIPListeners(raw)
}
func ValidName(value string) bool            { return wire.ValidName(value) }
func PublicProxyAddress(address string) bool { return wire.PublicProxyAddress(address) }
func ValidateMemberOutbounds(raw json.RawMessage, tags []string) error {
	return wire.ValidateMemberOutbounds(raw, tags)
}
func AuxiliaryInboundTags(raw json.RawMessage) ([]string, error) {
	return wire.AuxiliaryInboundTags(raw)
}
func Clone[T any](value T) T                   { return wire.Clone(value) }
func CommandNames() []string                   { return append([]string(nil), wire.CommandNames...) }
func CommandTimeout(name string) time.Duration { return wire.CommandTimeout(name) }
func Schemas() map[string]any                  { return wire.Schemas() }
