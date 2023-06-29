module github.com/sagernet/sing-box

go 1.18

require (
	berty.tech/go-libtor v1.0.385
	github.com/Dreamacro/clash v1.16.0
	github.com/caddyserver/certmagic v0.18.2
	github.com/cretz/bine v0.2.0
	github.com/dustin/go-humanize v1.0.1
	github.com/fsnotify/fsnotify v1.6.0
	github.com/go-chi/chi/v5 v5.0.8
	github.com/go-chi/cors v1.2.1
	github.com/go-chi/render v1.0.2
	github.com/gofrs/uuid/v5 v5.0.0
	github.com/insomniacslk/dhcp v0.0.0-20230612134759-b20c9ba983df
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mholt/acmez v1.2.0
	github.com/miekg/dns v1.1.55
	github.com/ooni/go-libtor v1.1.8
	github.com/oschwald/maxminddb-golang v1.11.0
	github.com/pires/go-proxyproto v0.7.0
	github.com/sagernet/cloudflare-tls v0.0.0-20221031050923-d70792f4c3a0
	github.com/sagernet/gomobile v0.0.0-20230413023804-244d7ff07035
	github.com/sagernet/gvisor v0.0.0-20230627031050-1ab0276e0dd2
	github.com/sagernet/quic-go v0.0.0-20230615020047-10f05c797c02
	github.com/sagernet/reality v0.0.0-20230406110435-ee17307e7691
	github.com/sagernet/sing v0.2.7
	github.com/sagernet/sing-dns v0.1.6
	github.com/sagernet/sing-mux v0.1.0
	github.com/sagernet/sing-shadowsocks v0.2.2
	github.com/sagernet/sing-shadowsocks2 v0.1.1
	github.com/sagernet/sing-shadowtls v0.1.2
	github.com/sagernet/sing-tun v0.1.8
	github.com/sagernet/sing-vmess v0.1.6
	github.com/sagernet/smux v0.0.0-20230312102458-337ec2a5af37
	github.com/sagernet/tfo-go v0.0.0-20230303015439-ffcfd8c41cf9
	github.com/sagernet/utls v0.0.0-20230309024959-6732c2ab36f2
	github.com/sagernet/websocket v0.0.0-20220913015213-615516348b4e
	github.com/sagernet/wireguard-go v0.0.0-20230420044414-a7bac1754e77
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.4
	go.etcd.io/bbolt v1.3.7
	go.uber.org/zap v1.24.0
	go4.org/netipx v0.0.0-20230303233057-f1b76eb4bb35
	golang.org/x/crypto v0.10.0
	golang.org/x/exp v0.0.0-20230522175609-2e198f4a06a1
	golang.org/x/net v0.11.0
	golang.org/x/sys v0.9.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
	google.golang.org/grpc v1.56.1
	google.golang.org/protobuf v1.30.0
)

//replace github.com/sagernet/sing => ../sing
replace github.com/sagernet/sing-shadowtls => github.com/maskedeken/sing-shadowtls v0.0.0-20230619011904-e0bd1120de59

replace github.com/sagernet/sing-mux => github.com/maskedeken/sing-mux v0.0.0-20230619011536-55d9ba08bd0a

replace github.com/sagernet/sing-shadowsocks2 => github.com/maskedeken/sing-shadowsocks2 v0.0.0-20230620020045-7310bf703e65

require (
	github.com/Dreamacro/protobytes v0.0.0-20230324064118-87bc784139cd // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/cloudflare/circl v1.2.1-0.20221019164342-6ab4dfed8f3c // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.15.15 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/onsi/ginkgo/v2 v2.2.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/qtls-go1-18 v0.2.0 // indirect
	github.com/quic-go/qtls-go1-19 v0.3.2 // indirect
	github.com/quic-go/qtls-go1-20 v0.2.2 // indirect
	github.com/sagernet/go-tun2socks v1.16.12-0.20220818015926-16cb67876a61 // indirect
	github.com/sagernet/netlink v0.0.0-20220905062125-8043b4a9aa97 // indirect
	github.com/scjalliance/comshim v0.0.0-20230315213746-5e51f40bd3b9 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.11.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.org/x/tools v0.10.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.2.1 // indirect
)
