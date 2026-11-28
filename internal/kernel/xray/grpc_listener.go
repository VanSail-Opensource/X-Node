// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Adapted from XTLS/Xray-core transport/internet/grpc at 676eaf66f8f0.
package xray

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	grpcconfig "github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const synchronousGRPCProtocol = "xnode-grpc-listener"

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(synchronousGRPCProtocol, func() any { return new(grpcconfig.Config) }))
	common.Must(internet.RegisterTransportListener(synchronousGRPCProtocol, listenSynchronousGRPC))
}

// enableSynchronousGRPC adapts only a cloned receiver, keeping the prepared
// configuration and native outbound dialers on the public grpc protocol.
func enableSynchronousGRPC(cfg *core.InboundHandlerConfig) error {
	if cfg == nil {
		return errors.New("native inbound is missing")
	}
	receiver, err := receiverSettings(cfg)
	if err != nil {
		return err
	}
	stream := receiver.GetStreamSettings()
	if stream.GetProtocolName() != "grpc" {
		return nil
	}
	settings, err := stream.GetEffectiveTransportSettings()
	if err != nil {
		return err
	}
	if _, ok := settings.(*grpcconfig.Config); !ok {
		return errors.New("invalid native gRPC transport settings")
	}
	stream.ProtocolName = synchronousGRPCProtocol
	for _, transport := range stream.GetTransportSettings() {
		if transport.GetUnifiedProtocolName() == "grpc" {
			transport.ProtocolName = synchronousGRPCProtocol
		}
	}
	cfg.ReceiverSettings = serial.ToTypedMessage(receiver)
	return nil
}

// Serve and the inbound worker can both close the socket. Guard the underlying
// transport so Close also owns the bind if called before Serve ever runs.
type grpcBoundTransport struct {
	net.Listener
	once sync.Once
}

func (l *grpcBoundTransport) Close() error {
	var err error
	l.once.Do(func() { err = l.Listener.Close() })
	return err
}

type synchronousGRPCListener struct {
	encoding.UnimplementedGRPCServiceServer
	*grpcBoundTransport
	ctx                  context.Context
	handler              internet.ConnHandler
	trustedXForwardedFor []string
	server               *grpc.Server
}

func (l *synchronousGRPCListener) Tun(server encoding.GRPCService_TunServer) error {
	ctx, cancel := context.WithCancel(l.ctx)
	defer cancel()
	l.handler(encoding.NewHunkConn(server, cancel, l.trustedXForwardedFor))
	<-ctx.Done()
	return nil
}

func (l *synchronousGRPCListener) TunMulti(server encoding.GRPCService_TunMultiServer) error {
	ctx, cancel := context.WithCancel(l.ctx)
	defer cancel()
	l.handler(encoding.NewMultiHunkConn(server, cancel, l.trustedXForwardedFor))
	<-ctx.Done()
	return nil
}

func (l *synchronousGRPCListener) Close() error {
	l.server.Stop()
	return l.grpcBoundTransport.Close()
}

func listenSynchronousGRPC(ctx context.Context, address net.Address, port net.Port, settings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if settings == nil {
		return nil, errors.New("invalid native gRPC transport settings")
	}
	c, ok := settings.ProtocolSettings.(*grpcconfig.Config)
	if !ok || c == nil {
		return nil, errors.New("invalid native gRPC transport settings")
	}
	var addr net.Addr
	if port == 0 {
		addr = &net.UnixAddr{Name: address.Domain(), Net: "unix"}
	} else {
		addr = &net.TCPAddr{IP: address.IP(), Port: int(port)}
	}
	var options []grpc.ServerOption
	if config := tls.ConfigFromStreamSettings(settings); config != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(config.GetTLSConfig(tls.WithNextProto("h2")))))
	}
	if c.IdleTimeout > 0 || c.HealthCheckTimeout > 0 {
		options = append(options, grpc.KeepaliveParams(keepalive.ServerParameters{
			Time: time.Second * time.Duration(c.IdleTimeout), Timeout: time.Second * time.Duration(c.HealthCheckTimeout),
		}))
	}
	var bound net.Listener
	var err error
	if settings.FinalMask != nil {
		bound, err = settings.FinalMask.Listen(ctx, addr)
	} else {
		bound, err = internet.ListenSystem(ctx, addr, settings.SocketSettings)
	}
	if err != nil {
		return nil, err
	}
	l := &synchronousGRPCListener{
		ctx: ctx, handler: handler, server: grpc.NewServer(options...),
	}
	if socket := settings.SocketSettings; socket != nil {
		l.trustedXForwardedFor = socket.TrustedXForwardedFor
		if socket.AcceptProxyProtocol {
			xerrors.LogWarning(ctx, "accepting PROXY protocol")
		}
	}
	service, tun, multi := grpcListenerNames(c.ServiceName)
	encoding.RegisterGRPCServiceServerX(l.server, l, service, tun, multi)
	if config := reality.ConfigFromStreamSettings(settings); config != nil {
		bound = goreality.NewListener(bound, config.GetREALITYConfig())
	}
	l.grpcBoundTransport = &grpcBoundTransport{Listener: bound}
	xerrors.LogDebug(ctx, "gRPC listen for service name `"+service+"` tun `"+tun+"` multi tun `"+multi+"`")
	go func() {
		if err := l.server.Serve(l.grpcBoundTransport); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			xerrors.LogInfoInner(ctx, err, "Listener for gRPC ended")
		}
	}()
	return l, nil
}

// Preserve upstream's escaped, segmented service and stream naming rules.
func grpcListenerNames(path string) (service, tun, multi string) {
	if !strings.HasPrefix(path, "/") {
		return url.PathEscape(path), "Tun", "TunMulti"
	}
	last := strings.LastIndex(path, "/")
	parts := strings.Split(path[1:max(last, 1)], "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	streams := strings.Split(path[last+1:], "|")
	second := 0
	if len(streams) > 1 {
		second = 1
	}
	return strings.Join(parts, "/"), url.PathEscape(streams[0]), url.PathEscape(streams[second])
}
