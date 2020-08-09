package rules

import (
	"strconv"

	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type Port struct {
	adapter  C.AdapterName
	port     string
	isSource bool
}

func (p *Port) RuleType() C.RuleType {
	if p.isSource {
		return C.SrcPort
	}
	return C.DstPort
}

func (p *Port) Match(metadata *C.Metadata) *C.AdapterName {
	port := metadata.DstPort
	if p.isSource {
		port = metadata.SrcPort
	}
	if port == p.port {
		return &p.adapter
	}
	return nil
}

func (d *Port) Adapter() C.AdapterName {
	return d.adapter
}

func (p *Port) Payload() string {
	return p.port
}

func (p *Port) ShouldResolveIP() bool {
	return false
}

func NewPort(port string, adapter constant.AdapterName, isSource bool) (*Port, error) {
	_, err := strconv.Atoi(port)
	if err != nil {
		return nil, errPayload
	}
	return &Port{
		adapter:  adapter,
		port:     port,
		isSource: isSource,
	}, nil
}
