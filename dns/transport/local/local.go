//go:build !darwin

package local

import (
	"context"
	"net"
	"net/netip"
	"runtime"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.LocalDNSServerOptions](registry, C.DNSTypeLocal, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

type Transport struct {
	dns.TransportAdapter
	ctx      context.Context
	logger   logger.ContextLogger
	hosts    *hosts.File
	dialer   N.Dialer
	preferGo bool
	resolved ResolvedResolver
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.LocalDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewLocalDialer(ctx, options)
	if err != nil {
		return nil, err
	}
	return &Transport{
		TransportAdapter: dns.NewTransportAdapterWithLocalOptions(C.DNSTypeLocal, tag, options),
		ctx:              ctx,
		logger:           logger,
		hosts:            hosts.NewFile(hosts.DefaultPath),
		dialer:           transportDialer,
		preferGo:         options.PreferGo,
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		if !t.preferGo {
			if isSystemdResolvedManaged() {
				resolvedResolver, err := NewResolvedResolver(t.ctx, t.logger)
				if err == nil {
					err = resolvedResolver.Start()
					if err == nil {
						t.resolved = resolvedResolver
					} else {
						t.logger.Warn(E.Cause(err, "initialize resolved resolver"))
					}
				}
			}
		}
	}
	return nil
}

func (t *Transport) Close() error {
	if t.resolved != nil {
		return t.resolved.Close()
	}
	return nil
}

func (t *Transport) Reset() {
}

func (t *Transport) lookupIP(ctx context.Context, msgId uint16, question mDNS.Question) (*mDNS.Msg, error) {
	domain := dns.FqdnToDomain(question.Name)

	ips, err := net.LookupIP(domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, dns.RcodeError(3) // NXDOMAIN
		}
		return nil, err
	}

	var addresses []netip.Addr
	for _, ip := range ips {
		parsed, err := netip.ParseAddr(ip.String())
		if err != nil {
			continue
		}
		if (question.Qtype == mDNS.TypeA && parsed.Is4()) ||
			(question.Qtype == mDNS.TypeAAAA && parsed.Is6()) {
			addresses = append(addresses, parsed)
		}
	}

	if len(addresses) == 0 {
		return nil, dns.RcodeError(0) // NOERROR but empty answer
	}

	return dns.FixedResponse(msgId, question, addresses, C.DefaultDNSTTL), nil
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.resolved != nil {
		return t.resolved.Exchange(ctx, message)
	}
	question := message.Question[0]
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		addresses := t.hosts.Lookup(dns.FqdnToDomain(question.Name))
		if len(addresses) > 0 {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
		// Use net.LookupIP on Android or when preferGo is set
		if runtime.GOOS == "android" || t.preferGo {
			return t.lookupIP(ctx, message.Id, question)
		}
	}
	return t.exchange(ctx, message, question.Name)
}
