package agent

import (
	"errors"
	"time"

	"github.com/VanSail-Opensource/X-Node/internal/protocol"
	"github.com/VanSail-Opensource/X-Node/internal/sessions"
)

func (a *Agent) connectionCommand(name string, args []byte) (any, error) {
	switch name {
	case "connections.list":
		var p struct {
			After string `json:"after,omitempty"`
			Limit int    `json:"limit,omitempty"`
		}
		if e := protocol.Decode(args, &p); e != nil {
			return nil, e
		}
		return a.Registry.List(p.After, p.Limit), nil
	case "users.active_ips":
		var p struct {
			UserID int `json:"user_id,omitempty"`
		}
		if e := protocol.Decode(args, &p); e != nil {
			return nil, e
		}
		if p.UserID < 0 {
			return nil, errors.New("invalid user ID")
		}
		return a.Registry.ActiveIPs(p.UserID), nil
	case "ips.control":
		var p protocol.IPControl
		if e := protocol.Decode(args, &p); e != nil {
			return nil, e
		}
		ip, e := sessions.CanonicalIP(p.SourceIP)
		if e != nil {
			return nil, e
		}
		if p.UserID < 0 || p.BlockSeconds < 0 || p.BlockSeconds > 604800 || p.Unblock && p.BlockSeconds > 0 || !p.Drop && !p.Unblock && p.BlockSeconds == 0 {
			return nil, errors.New("invalid IP control")
		}
		var subject *protocol.User
		if p.UserID > 0 {
			user, authorization, err := a.Store.SubjectView(p.UserID)
			if err != nil {
				return nil, err
			}
			subject = &user
			a.Registry.ApplyAuthorization(authorization)
		}
		key := sessions.IPBlockKey(p.UserID, ip)
		block := protocol.IPBlock{SourceIP: ip, UserID: p.UserID}
		if p.BlockSeconds > 0 {
			block.Until = time.Now().Add(time.Duration(p.BlockSeconds) * time.Second)
		}
		if p.BlockSeconds > 0 || p.Unblock {
			authorization, err := a.Store.BlockIPView(key, block, subject)
			if err != nil {
				return nil, err
			}
			a.Registry.ApplyAuthorization(authorization)
		}
		dropped := 0
		if p.Drop {
			dropped, e = a.Registry.DropIPSubject(ip, subject)
			if e != nil {
				return nil, e
			}
		}
		return map[string]any{"source_ip": ip, "user_id": p.UserID, "dropped": dropped, "blocked_until": block.Until}, nil
	case "connections.close":
		var p struct {
			ID         string `json:"id"`
			UserID     int    `json:"user_id,omitempty"`
			InboundTag string `json:"inbound_tag,omitempty"`
		}
		if e := protocol.Decode(args, &p); e != nil {
			return nil, e
		}
		if p.UserID > 0 {
			a.Registry.CloseUser(p.UserID, p.InboundTag)
			return map[string]bool{"closed": true}, nil
		}
		return map[string]bool{"closed": a.Registry.CloseConnection(p.ID)}, nil

	default:
		return nil, errors.New("unsupported connection command")
	}
}
