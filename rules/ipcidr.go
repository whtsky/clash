package rules

import (
	"net"

	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type IPCIDROption func(*IPCIDR)

func WithIPCIDRSourceIP(b bool) IPCIDROption {
	return func(i *IPCIDR) {
		i.isSourceIP = b
	}
}

func WithIPCIDRNoResolve(noResolve bool) IPCIDROption {
	return func(i *IPCIDR) {
		i.noResolveIP = noResolve
	}
}

type IPCIDR struct {
	ipnet       *net.IPNet
	adapter     constant.AdapterName
	isSourceIP  bool
	noResolveIP bool
}

func (i *IPCIDR) RuleType() C.RuleType {
	if i.isSourceIP {
		return C.SrcIPCIDR
	}
	return C.IPCIDR
}

func (i *IPCIDR) Match(metadata *C.Metadata) *C.AdapterName {
	ip := metadata.DstIP
	if i.isSourceIP {
		ip = metadata.SrcIP
	}
	if ip != nil && i.ipnet.Contains(ip) {
		return &i.adapter
	}
	return nil
}

func (d *IPCIDR) Adapter() C.AdapterName {
	return d.adapter
}

func (i *IPCIDR) Payload() string {
	return i.ipnet.String()
}

func (i *IPCIDR) NoResolveIP() bool {
	return i.noResolveIP
}

func (i *IPCIDR) IsSourceIP() bool {
	return i.isSourceIP
}

func (i *IPCIDR) GetIpNet() *net.IPNet {
	return i.ipnet
}

func NewIPCIDR(s string, adapter constant.AdapterName, opts ...IPCIDROption) (*IPCIDR, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, errPayload
	}

	ipcidr := &IPCIDR{
		ipnet:   ipnet,
		adapter: adapter,
	}

	for _, o := range opts {
		o(ipcidr)
	}

	return ipcidr, nil
}
