//go:build with_utls

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
	utls "github.com/sagernet/utls"
)

const ivLen = 32 // bytes

var _ ConfigCompat = (*JLSClientConfig)(nil)

type JLSClientConfig struct {
	uClient  *UTLSClientConfig
	password []byte
	iv       []byte
}

func (s *JLSClientConfig) ServerName() string {
	return s.uClient.ServerName()
}

func (s *JLSClientConfig) SetServerName(serverName string) {
	s.uClient.SetServerName(serverName)
}

func (s *JLSClientConfig) NextProtos() []string {
	return s.uClient.NextProtos()
}

func (s *JLSClientConfig) SetNextProtos(nextProto []string) {
	s.uClient.SetNextProtos(nextProto)
}

func (s *JLSClientConfig) Config() (*STDConfig, error) {
	return nil, E.New("unsupported usage for JLS")
}

func (s *JLSClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, s)
}

func (s *JLSClientConfig) Clone() Config {
	return &JLSClientConfig{
		s.uClient.Clone().(*UTLSClientConfig),
		s.password,
		s.iv,
	}
}

func (s *JLSClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	uConfig := s.uClient.config.Clone()
	uConfig.InsecureSkipVerify = true
	uConn := utls.UClient(conn, uConfig, s.uClient.id)
	err := uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	setZero(hello.Raw[6 : 6+32])
	s.fillFakeRandom(hello.Raw, hello.Random[:0])
	copy(hello.Raw[6:], hello.Random)

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	srvHello := uConn.HandshakeState.ServerHello
	raw := make([]byte, len(srvHello.Raw))
	copy(raw, srvHello.Raw)
	setZero(raw[6 : 6+32])
	if !s.checkFakeRandom(raw, srvHello.Random) {
		// fallback
		go uTLSClientFallback(uConn, s.uClient.ServerName(), s.uClient.id)
		return nil, E.New("JLS verification failed")
	}

	return &utlsConnWrapper{
		UConn: uConn,
	}, nil
}

func (s *JLSClientConfig) fillFakeRandom(authData []byte, dst []byte) {
	pwd := sha256.New()
	pwd.Write(append(s.password, authData...))
	iv := sha256.New()
	iv.Write(append(s.iv, authData...))

	random := make([]byte, 16)
	rand.Read(random)
	aesBlock, _ := aes.NewCipher(pwd.Sum(nil))
	aesGcmCipher, _ := cipher.NewGCMWithNonceSize(aesBlock, ivLen)
	aesGcmCipher.Seal(dst, iv.Sum(nil), random, nil)
}

func (s *JLSClientConfig) checkFakeRandom(authData []byte, random []byte) bool {
	pwd := sha256.New()
	pwd.Write(append(s.password, authData...))
	iv := sha256.New()
	iv.Write(append(s.iv, authData...))

	aesBlock, _ := aes.NewCipher(pwd.Sum(nil))
	aesGcmCipher, _ := cipher.NewGCMWithNonceSize(aesBlock, ivLen)
	_, err := aesGcmCipher.Open(nil, iv.Sum(nil), random, nil)
	return err == nil
}

func setZero(dst []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = 0
	}
}

func NewJLSlient(router adapter.Router, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by JLS client")
	}

	if options.JLS.Password == "" {
		return nil, E.New("empty password")
	}

	if options.JLS.IV == "" {
		return nil, E.New("empty random")
	}

	uClient, err := NewUTLSClient(router, serverAddress, options)
	if err != nil {
		return nil, err
	}

	return &JLSClientConfig{
		uClient,
		[]byte(options.JLS.Password),
		[]byte(options.JLS.IV),
	}, nil
}
