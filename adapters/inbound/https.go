package inbound

import (
	"net"
	"net/http"

	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/context"
)

// NewHTTPS recieve CONNECT request and return ConnContext
func NewHTTPS(request *http.Request, conn net.Conn) *context.ConnContext {
	metadata := parseHTTPAddr(request)
	metadata.Type = C.HTTPCONNECT
	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		metadata.SrcIP = ip
		metadata.SrcPort = port
	}
	return context.NewConnContext(conn, metadata)
}
