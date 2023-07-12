package outbound

import (
	"context"
	"net"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (h *Direct) newPacketConn(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	udpConn, err := h.dialer.DialContext(ctx, N.NetworkUDP, destination)
	if err != nil {
		return nil, err
	}

	return bufio.NewUnbindPacketConn(udpConn), nil
}
