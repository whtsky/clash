package rules

import (
	"strings"

	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type DomainKeyword struct {
	keyword string
	adapter constant.AdapterName
}

func (dk *DomainKeyword) RuleType() C.RuleType {
	return C.DomainKeyword
}

func (dk *DomainKeyword) Match(metadata *C.Metadata) *C.AdapterName {
	if metadata.AddrType != C.AtypDomainName {
		return nil
	}
	domain := metadata.Host
	if strings.Contains(domain, dk.keyword) {
		return &dk.adapter
	}
	return nil
}

func (d *DomainKeyword) Adapter() C.AdapterName {
	return d.adapter
}

func (dk *DomainKeyword) Payload() string {
	return dk.keyword
}

func (dk *DomainKeyword) ShouldResolveIP() bool {
	return false
}

func NewDomainKeyword(keyword string, adapter constant.AdapterName) *DomainKeyword {
	return &DomainKeyword{
		keyword: strings.ToLower(keyword),
		adapter: adapter,
	}
}
