package rules

import (
	"strings"

	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type DomainSuffix struct {
	suffix  string
	adapter constant.AdapterName
}

func (ds *DomainSuffix) RuleType() C.RuleType {
	return C.DomainSuffix
}

func (ds *DomainSuffix) Match(metadata *C.Metadata) *C.AdapterName {
	if metadata.AddrType != C.AtypDomainName {
		return nil
	}
	domain := metadata.Host
	if strings.HasSuffix(domain, "."+ds.suffix) || domain == ds.suffix {
		return &ds.adapter
	}
	return nil
}

func (d *DomainSuffix) Adapter() C.AdapterName {
	return d.adapter
}

func (ds *DomainSuffix) Payload() string {
	return ds.suffix
}

func (ds *DomainSuffix) ShouldResolveIP() bool {
	return false
}

func NewDomainSuffix(suffix string, adapter constant.AdapterName) *DomainSuffix {
	return &DomainSuffix{
		suffix:  strings.ToLower(suffix),
		adapter: adapter,
	}
}
