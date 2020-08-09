package rules

import (
	"strings"

	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type Domain struct {
	domain  string
	adapter constant.AdapterName
}

func (d *Domain) RuleType() C.RuleType {
	return C.Domain
}

func (d *Domain) Match(metadata *C.Metadata) *C.AdapterName {
	if metadata.AddrType != C.AtypDomainName {
		return nil
	}
	if metadata.Host == d.domain {
		return &d.adapter
	}
	return nil
}

func (d *Domain) Adapter() C.AdapterName {
	return d.adapter
}

func (d *Domain) Payload() string {
	return d.domain
}

func (d *Domain) ShouldResolveIP() bool {
	return false
}

func NewDomain(domain string, adapter constant.AdapterName) *Domain {
	return &Domain{
		domain:  strings.ToLower(domain),
		adapter: adapter,
	}
}
