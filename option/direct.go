package option

type DirectInboundOptions struct {
	ListenOptions
	Network         NetworkList `json:"network,omitempty"`
	OverrideAddress string      `json:"override_address,omitempty"`
	OverridePort    uint16      `json:"override_port,omitempty"`
}

type DirectOutboundOptions struct {
	DialerOptions
	OverrideAddress string    `json:"override_address,omitempty"`
	OverridePort    uint16    `json:"override_port,omitempty"`
	ProxyProtocol   uint8     `json:"proxy_protocol,omitempty"`
	Fragment        *Fragment `json:"fragment,omitempty"`
}

type Fragment struct {
	Length   string `json:"length"`
	Interval string `json:"interval"`
}
