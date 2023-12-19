package outbound

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var (
	_ adapter.Outbound = (*Direct)(nil)
	_ N.ParallelDialer = (*Direct)(nil)
)

type Direct struct {
	myOutboundAdapter
	dialer              N.Dialer
	domainStrategy      dns.DomainStrategy
	fallbackDelay       time.Duration
	overrideOption      int
	overrideDestination M.Socksaddr
	fragment            *Fragment
}

type Fragment struct {
	MinInterval int32
	MaxInterval int32
	MinLength   int32
	MaxLength   int32
}

func NewDirect(router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (*Direct, error) {
	options.UDPFragmentDefault = true
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Direct{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeDirect,
			network:      []string{N.NetworkTCP, N.NetworkUDP},
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		domainStrategy: dns.DomainStrategy(options.DomainStrategy),
		fallbackDelay:  time.Duration(options.FallbackDelay),
		dialer:         outboundDialer,
	}
	if options.ProxyProtocol != 0 {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	if options.OverrideAddress != "" && options.OverridePort != 0 {
		outbound.overrideOption = 1
		outbound.overrideDestination = M.ParseSocksaddrHostPort(options.OverrideAddress, options.OverridePort)
	} else if options.OverrideAddress != "" {
		outbound.overrideOption = 2
		outbound.overrideDestination = M.ParseSocksaddrHostPort(options.OverrideAddress, options.OverridePort)
	} else if options.OverridePort != 0 {
		outbound.overrideOption = 3
		outbound.overrideDestination = M.Socksaddr{Port: options.OverridePort}
	}
	if options.Fragment != nil {
		if len(options.Fragment.Interval) == 0 || len(options.Fragment.Length) == 0 {
			return nil, E.New("Invalid interval or length")
		}
		intervalMinMax := strings.Split(options.Fragment.Interval, "-")
		var minInterval, maxInterval int64
		var err, err2 error
		if len(intervalMinMax) == 2 {
			minInterval, err = strconv.ParseInt(intervalMinMax[0], 10, 64)
			maxInterval, err2 = strconv.ParseInt(intervalMinMax[1], 10, 64)
		} else {
			minInterval, err = strconv.ParseInt(intervalMinMax[0], 10, 64)
			maxInterval = minInterval
		}
		if err != nil {
			return nil, E.Cause(err, "Invalid minimum interval: ")
		}
		if err2 != nil {
			return nil, E.Cause(err2, "Invalid maximum interval: ")
		}

		lengthMinMax := strings.Split(options.Fragment.Length, "-")
		var minLength, maxLength int64
		if len(lengthMinMax) == 2 {
			minLength, err = strconv.ParseInt(lengthMinMax[0], 10, 64)
			maxLength, err2 = strconv.ParseInt(lengthMinMax[1], 10, 64)

		} else {
			minLength, err = strconv.ParseInt(lengthMinMax[0], 10, 64)
			maxLength = minLength
		}
		if err != nil {
			return nil, E.Cause(err, "Invalid minimum length: ")
		}
		if err2 != nil {
			return nil, E.Cause(err2, "Invalid maximum length: ")
		}

		if minInterval > maxInterval {
			minInterval, maxInterval = maxInterval, minInterval
		}
		if minLength > maxLength {
			minLength, maxLength = maxLength, minLength
		}

		outbound.fragment = &Fragment{
			MinInterval: int32(minInterval),
			MaxInterval: int32(maxInterval),
			MinLength:   int32(minLength),
			MaxLength:   int32(maxLength),
		}
	}
	return outbound, nil
}

func (h *Direct) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch h.overrideOption {
	case 1:
		destination = h.overrideDestination
	case 2:
		newDestination := h.overrideDestination
		newDestination.Port = destination.Port
		destination = newDestination
	case 3:
		destination.Port = h.overrideDestination.Port
	}
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	conn, err := h.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	if network == N.NetworkTCP && h.fragment != nil {
		conn = &FragmentedClientHelloConn{
			Conn:        conn,
			ctx:         ctx,
			logger:      h.logger,
			maxLength:   int(h.fragment.MaxLength),
			minInterval: time.Duration(h.fragment.MinInterval) * time.Millisecond,
			maxInterval: time.Duration(h.fragment.MaxInterval) * time.Millisecond,
		}
	}
	return conn, nil
}

func (h *Direct) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	switch h.overrideOption {
	case 1, 2:
		// override address
		return h.DialContext(ctx, network, destination)
	case 3:
		destination.Port = h.overrideDestination.Port
	}
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	var domainStrategy dns.DomainStrategy
	if h.domainStrategy != dns.DomainStrategyAsIS {
		domainStrategy = h.domainStrategy
	} else {
		domainStrategy = dns.DomainStrategy(metadata.InboundOptions.DomainStrategy)
	}
	conn, err := N.DialParallel(ctx, h.dialer, network, destination, destinationAddresses, domainStrategy == dns.DomainStrategyPreferIPv6, h.fallbackDelay)
	if err != nil {
		return nil, err
	}
	if network == N.NetworkTCP && h.fragment != nil {
		conn = &FragmentedClientHelloConn{
			Conn:        conn,
			ctx:         ctx,
			logger:      h.logger,
			maxLength:   int(h.fragment.MaxLength),
			minInterval: time.Duration(h.fragment.MinInterval) * time.Millisecond,
			maxInterval: time.Duration(h.fragment.MaxInterval) * time.Millisecond,
		}
	}
	return conn, nil
}

func (h *Direct) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	originDestination := destination
	switch h.overrideOption {
	case 1:
		destination = h.overrideDestination
	case 2:
		newDestination := h.overrideDestination
		newDestination.Port = destination.Port
		destination = newDestination
	case 3:
		destination.Port = h.overrideDestination.Port
	}
	if h.overrideOption == 0 {
		h.logger.InfoContext(ctx, "outbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	if originDestination != destination {
		conn = bufio.NewNATPacketConn(bufio.NewPacketConn(conn), destination, originDestination)
	}
	return conn, nil
}

func (h *Direct) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *Direct) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

// stolen from github.com/xtls/xray-core/transport/internet/reality
func randBetween(left int64, right int64) int64 {
	if left == right {
		return left
	}
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(right-left))
	return left + bigInt.Int64()
}

type FragmentedClientHelloConn struct {
	net.Conn
	ctx         context.Context
	logger      log.ContextLogger
	PacketCount int
	minLength   int
	maxLength   int
	minInterval time.Duration
	maxInterval time.Duration
}

func (c *FragmentedClientHelloConn) Write(b []byte) (n int, err error) {
	if c.PacketCount == 0 {
		if len(b) >= 5 && b[0] == 22 {
			n, err = sendFragmentedClientHello(c, b, c.minLength, c.maxLength)
		} else {
			n, err = c.Conn.Write(b)
		}

		if err == nil {
			c.PacketCount++
		}

		return
	}

	return c.Conn.Write(b)
}

func (c *FragmentedClientHelloConn) Upstream() any {
	return c.Conn
}

func sendFragmentedClientHello(conn *FragmentedClientHelloConn, clientHello []byte, minFragmentSize, maxFragmentSize int) (n int, err error) {
	if len(clientHello) < 5 || clientHello[0] != 22 {
		return 0, E.New("not a valid TLS ClientHello message")
	}

	clientHelloLen := (int(clientHello[3]) << 8) | int(clientHello[4])
	if conn.logger != nil {
		conn.logger.InfoContext(conn.ctx, "Sending fragmented TLS client hello: ", clientHelloLen)
	}

	clientHelloData := clientHello[5:]
	i := 0
	for {
		fragmentEnd := i + int(randBetween(int64(minFragmentSize), int64(maxFragmentSize)))
		if fragmentEnd > clientHelloLen {
			fragmentEnd = clientHelloLen
		}

		fragment := clientHelloData[i:fragmentEnd]
		i = fragmentEnd

		err = writeFragmentedRecord(conn, 22, fragment, clientHello)
		if err != nil {
			return 0, err
		}

		if i >= clientHelloLen {
			break
		}

		randomInterval := randBetween(int64(conn.minInterval), int64(conn.maxInterval))
		if randomInterval > 0 {
			time.Sleep(time.Duration(randomInterval))
		}
	}

	return len(clientHello), nil
}

func writeFragmentedRecord(c *FragmentedClientHelloConn, contentType uint8, data []byte, clientHello []byte) error {
	header := make([]byte, 5)
	header[0] = byte(clientHello[0])

	tlsVersion := (int(clientHello[1]) << 8) | int(clientHello[2])
	binary.BigEndian.PutUint16(header[1:], uint16(tlsVersion))

	binary.BigEndian.PutUint16(header[3:], uint16(len(data)))
	_, err := c.Conn.Write(append(header, data...))

	return err
}
