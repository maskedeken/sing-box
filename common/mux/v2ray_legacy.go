package mux

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

type V2RayLegacyRouter struct {
	router adapter.ConnectionRouterEx
	logger logger.ContextLogger
}

func NewV2RayLegacyRouter(router adapter.ConnectionRouterEx, logger logger.ContextLogger) adapter.ConnectionRouterEx {
	return &V2RayLegacyRouter{router, logger}
}

func (r *V2RayLegacyRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if metadata.Destination.Fqdn == vmess.MuxDestination.Fqdn {
		r.logger.InfoContext(ctx, "inbound legacy multiplex connection")
		return vmess.HandleMuxConnection(ctx, conn, metadata.Source, adapter.NewRouteHandlerEx(metadata, r.router))
	}
	return r.router.RouteConnection(ctx, conn, metadata)
}

func (r *V2RayLegacyRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return r.router.RoutePacketConnection(ctx, conn, metadata)
}

func (r *V2RayLegacyRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if metadata.Destination.Fqdn == vmess.MuxDestination.Fqdn {
		r.logger.InfoContext(ctx, "inbound legacy multiplex connection")
		vmess.HandleMuxConnection(ctx, conn, metadata.Source, adapter.NewRouteHandlerEx(metadata, r.router))
		return
	}

	r.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (r *V2RayLegacyRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
