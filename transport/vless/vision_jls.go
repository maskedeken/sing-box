//go:build with_jls_server

package vless

import (
	"net"
	"reflect"
	"unsafe"

	JLS "github.com/JimmyHuang454/JLS-go/tls"
	"github.com/sagernet/sing/common"
)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		tlsConn, loaded := common.Cast[*JLS.Conn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), uintptr(unsafe.Pointer(tlsConn))
	})
}
