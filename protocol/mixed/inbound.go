package mixed

import (
	std_bufio "bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	udpnat "github.com/sagernet/sing/common/udpnat2"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.HTTPMixedInboundOptions](registry, C.TypeMixed, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type udpFilter struct {
	ips sync.Map
}

func (f *udpFilter) add(addr net.Addr) {
	ip, _, _ := net.SplitHostPort(addr.String())
	f.ips.Store(ip, true)
}

func (f *udpFilter) check(addr net.Addr) bool {
	ip, _, _ := net.SplitHostPort(addr.String())
	_, ok := f.ips.Load(ip)
	return ok
}

func (f *udpFilter) checkSocksaddr(addr M.Socksaddr) bool {
	ip := addr.Addr.String()
	_, ok := f.ips.Load(ip)
	return ok
}

type Inbound struct {
	inbound.Adapter
	ctx           context.Context
	router        adapter.ConnectionRouterEx
	logger        log.ContextLogger
	listener      *listener.Listener
	authenticator *auth.Authenticator
	tlsConfig     tls.ServerConfig
	udpNat        *udpnat.Service
	udpFilter     *udpFilter
	udpTimeout    time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPMixedInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeMixed, tag),
		ctx:           ctx,
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: auth.NewAuthenticator(options.Users),
		udpTimeout:    udpTimeout,
	}
	if len(options.Users) > 0 {
		inbound.udpFilter = &udpFilter{}
	}
	inbound.udpNat = udpnat.New(inbound, inbound.preparePacketConnection, udpTimeout, false)
	listenerOpts := listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           options.Network.Build(),
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
		PacketHandler:     inbound,
		SetSystemProxy:    options.SetSystemProxy,
		SystemProxySOCKS:  true,
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServerWithOptions(tls.ServerOptions{
			Context:        ctx,
			Logger:         logger,
			Options:        common.PtrValueOrDefault(options.TLS),
			KTLSCompatible: true,
		})
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}
	inbound.listener = listener.New(listenerOpts)
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(
		h.listener,
		h.tlsConfig,
	)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := h.newConnection(ctx, conn, metadata, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) error {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			return E.Cause(err, "TLS handshake")
		}
		conn = tlsConn
	}
	reader := std_bufio.NewReader(conn)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		return E.Cause(err, "peek first byte")
	}
	switch headerBytes[0] {
	case socks4.Version, socks5.Version:
		return socks.HandleConnectionEx(ctx, conn, reader, h.authenticator, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), h.listener, h.udpTimeout, metadata.Source, onClose)
	default:
		return http.HandleConnectionEx(ctx, conn, reader, h.authenticator, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), metadata.Source, onClose)
	}
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	if h.udpFilter != nil {
		h.udpFilter.add(conn.RemoteAddr())
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func decodeUDPPacket(buffer *buf.Buffer) (destination M.Socksaddr, payload []byte, err error) {
	if buffer.Len() < 5 {
		return M.Socksaddr{}, nil, E.New("insufficient length")
	}
	// Skip reserved bytes (0x00, 0x00) and fragment (0x00)
	if buffer.Byte(2) != 0 {
		return M.Socksaddr{}, nil, E.New("fragmented packet not supported")
	}
	buffer.Advance(3)
	// Parse address
	destination, err = M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return M.Socksaddr{}, nil, E.Cause(err, "read address")
	}
	payload = buffer.Bytes()
	return destination, payload, nil
}

func encodeUDPPacket(destination M.Socksaddr, payload []byte) (*buf.Buffer, error) {
	buffer := buf.NewSize(3 + M.SocksaddrSerializer.AddrPortLen(destination) + len(payload))
	buffer.WriteZeroN(2) // reserved
	buffer.WriteByte(0)  // fragment
	err := M.SocksaddrSerializer.WriteAddrPort(buffer, destination)
	if err != nil {
		buffer.Release()
		return nil, err
	}
	buffer.Write(payload)
	return buffer, nil
}

func (h *Inbound) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	// Check UDP filter if authentication is required
	if h.udpFilter != nil && !h.udpFilter.checkSocksaddr(source) {
		h.logger.DebugContext(h.ctx, "unauthorized UDP access from ", source)
		buffer.Release()
		return
	}
	// Decode SOCKS5 UDP packet
	destination, payload, err := decodeUDPPacket(buffer)
	if err != nil {
		h.logger.DebugContext(h.ctx, "failed to decode UDP packet from ", source, ": ", err)
		buffer.Release()
		return
	}
	// Copy payload because buffer will be released after this method
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)
	buffer.Release()
	// Forward to udpNat
	h.udpNat.NewPacket([][]byte{payloadCopy}, source, destination, nil)
}

func (h *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.logger.InfoContext(ctx, "inbound packet connection from ", source)
	h.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Source = source
	metadata.Destination = destination
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	return true, log.ContextWithNewID(h.ctx), &socksPacketWriter{h.listener.PacketWriter(), source, destination}, nil
}

type socksPacketWriter struct {
	writer N.PacketWriter
	source M.Socksaddr
	dest   M.Socksaddr
}

func (w *socksPacketWriter) WritePacket(buffer *buf.Buffer, addr M.Socksaddr) error {
	// Encode SOCKS5 UDP packet with original destination address (w.dest)
	encoded, err := encodeUDPPacket(w.dest, buffer.Bytes())
	if err != nil {
		buffer.Release()
		return err
	}
	defer encoded.Release()
	// Send back to client (w.source)
	return w.writer.WritePacket(encoded, w.source)
}
