//go:build !with_jls_server

package tls

import (
	"context"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewJLSServer(ctx context.Context, logger log.Logger, options option.InboundTLSOptions) (ServerConfig, error) {
	return nil, E.New(`JLS server is not included in this build, rebuild with -tags with_jls_server`)
}
