//go:build !android

package outbound

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *Direct) newPacketConn(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	if h.overrideOption == 0 {
		return conn, nil
	} else {
		return &overridePacketConn{bufio.NewPacketConn(conn), destination}, nil
	}
}

type overridePacketConn struct {
	N.NetPacketConn
	overrideDestination M.Socksaddr
}

func (c *overridePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	return c.NetPacketConn.WritePacket(buffer, c.overrideDestination)
}

func (c *overridePacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.NetPacketConn.WriteTo(p, c.overrideDestination.UDPAddr())
}

func (c *overridePacketConn) Upstream() any {
	return c.NetPacketConn
}
