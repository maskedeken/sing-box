//go:build with_jls_server

package tls

import (
	"context"
	"crypto/tls"
	"net"
	"os"

	JLS "github.com/JimmyHuang454/JLS-go/tls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type JLSServerConfig struct {
	config   *JLS.Config
	isCompat bool
}

// NextProtos implements tls.ServerConfig.
func (c *JLSServerConfig) NextProtos() []string {
	return c.config.NextProtos
}

// SetNextProtos implements tls.ServerConfig.
func (c *JLSServerConfig) SetNextProtos(nextProto []string) {
	c.config.NextProtos = nextProto
}

func (c *JLSServerConfig) ServerName() string {
	return c.config.ServerName
}

func (c *JLSServerConfig) SetServerName(serverName string) {
	c.config.ServerName = serverName
}

func (c *JLSServerConfig) Config() (*STDConfig, error) {
	return nil, E.New("unsupported usage for JLS")
}

func (c *JLSServerConfig) Client(conn net.Conn) (Conn, error) {
	return &JLSConnWrapper{JLS.Client(conn, c.config)}, nil
}

func (c *JLSServerConfig) Server(conn net.Conn) (Conn, error) {
	return &JLSConnWrapper{JLS.Server(conn, c.config)}, nil
}

func (c *JLSServerConfig) Clone() Config {
	return &JLSServerConfig{
		config: c.config.Clone(),
	}
}

func (c *JLSServerConfig) Start() error {
	return nil
}

func (c *JLSServerConfig) Close() error {
	return nil
}

func NewJLSServer(ctx context.Context, router adapter.Router, logger log.Logger, options option.InboundTLSOptions) (ServerConfig, error) {
	tlsConfig := &JLS.Config{}
	tlsConfig.Time = router.TimeFunc()

	if options.ServerName == "" {
		return nil, E.New("fallback website is needed.")
	}
	tlsConfig.ServerName = options.ServerName

	if len(options.ALPN) > 0 {
		tlsConfig.NextProtos = append(options.ALPN, tlsConfig.NextProtos...)
	}

	if options.CipherSuites != nil {
	find:
		for _, cipherSuite := range options.CipherSuites {
			for _, tlsCipherSuite := range tls.CipherSuites() {
				if cipherSuite == tlsCipherSuite.Name {
					tlsConfig.CipherSuites = append(tlsConfig.CipherSuites, tlsCipherSuite.ID)
					continue find
				}
			}
			return nil, E.New("unknown cipher_suite: ", cipherSuite)
		}
	}

	var certificate []byte
	var key []byte
	if options.Certificate != "" {
		certificate = []byte(options.Certificate)
	} else if options.CertificatePath != "" {
		content, err := os.ReadFile(options.CertificatePath)
		if err != nil {
			return nil, E.Cause(err, "read certificate")
		}
		certificate = content
	}
	if options.Key != "" {
		key = []byte(options.Key)
	} else if options.KeyPath != "" {
		content, err := os.ReadFile(options.KeyPath)
		if err != nil {
			return nil, E.Cause(err, "read key")
		}
		key = content
	}
	if certificate == nil {
		return nil, E.New("missing certificate")
	} else if key == nil {
		return nil, E.New("missing key")
	}

	cert, err := JLS.X509KeyPair(certificate, key)
	if err != nil {
		return nil, E.Cause(err, "parse x509 key pair")
	}

	tlsConfig.Certificates = []JLS.Certificate{cert}
	tlsConfig.JLSPWD = []byte(options.JLS.Password)
	tlsConfig.JLSIV = []byte(options.JLS.IV)
	tlsConfig.UseJLS = true

	return &JLSServerConfig{
		config:   tlsConfig,
		isCompat: false,
	}, nil
}

type JLSConnWrapper struct {
	*JLS.Conn
}

func (c *JLSConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *JLSConnWrapper) Upstream() any {
	return c.Conn
}
