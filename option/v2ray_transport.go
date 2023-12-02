package option

import (
	"github.com/sagernet/sing-box/common/json"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type _V2RayTransportOptions struct {
	Type               string                  `json:"type,omitempty"`
	HTTPOptions        V2RayHTTPOptions        `json:"-"`
	WebsocketOptions   V2RayWebsocketOptions   `json:"-"`
	QUICOptions        V2RayQUICOptions        `json:"-"`
	GRPCOptions        V2RayGRPCOptions        `json:"-"`
	HTTPUpgradeOptions V2RayHTTPUpgradeOptions `json:"-"`
}

type V2RayTransportOptions _V2RayTransportOptions

func (o V2RayTransportOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case "":
		return nil, nil
	case C.V2RayTransportTypeHTTP:
		v = o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = o.HTTPUpgradeOptions
	default:
		return nil, E.New("unknown transport type: " + o.Type)
	}
	return MarshallObjects((_V2RayTransportOptions)(o), v)
}

func (o *V2RayTransportOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_V2RayTransportOptions)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = &o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = &o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = &o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = &o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = &o.HTTPUpgradeOptions
	default:
		return E.New("unknown transport type: " + o.Type)
	}
	err = UnmarshallExcluded(bytes, (*_V2RayTransportOptions)(o), v)
	if err != nil {
		return err
	}
	return nil
}

type V2RayHTTPOptions struct {
	Host        Listable[string] `json:"host,omitempty"`
	Path        string           `json:"path,omitempty"`
	Method      string           `json:"method,omitempty"`
	Headers     HTTPHeader       `json:"headers,omitempty"`
	IdleTimeout Duration         `json:"idle_timeout,omitempty"`
	PingTimeout Duration         `json:"ping_timeout,omitempty"`
}

type V2RayWebsocketOptions struct {
	Path                string     `json:"path,omitempty"`
	Headers             HTTPHeader `json:"headers,omitempty"`
	MaxEarlyData        uint32     `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string     `json:"early_data_header_name,omitempty"`
}

type V2RayQUICOptions struct{}

type V2RayGRPCOptions struct {
	ServiceName         string   `json:"service_name,omitempty"`
	IdleTimeout         Duration `json:"idle_timeout,omitempty"`
	PingTimeout         Duration `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool     `json:"permit_without_stream,omitempty"`
	ForceLite           bool     `json:"-"` // for test
}

type V2RayHTTPUpgradeOptions struct {
	Host    string     `json:"host,omitempty"`
	Path    string     `json:"path,omitempty"`
	Headers HTTPHeader `json:"headers,omitempty"`
}
