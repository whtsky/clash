package rules

import (
	"github.com/whtsky/clash/constant"
	C "github.com/whtsky/clash/constant"
)

type Match struct {
	adapter constant.AdapterName
}

func (f *Match) RuleType() C.RuleType {
	return C.MATCH
}

func (f *Match) Match(metadata *C.Metadata) *C.AdapterName {
	return &f.adapter
}

func (d *Match) Adapter() C.AdapterName {
	return d.adapter
}

func (f *Match) Payload() string {
	return ""
}

func (f *Match) ShouldResolveIP() bool {
	return false
}

func NewMatch(adapter constant.AdapterName) *Match {
	return &Match{
		adapter: adapter,
	}
}
