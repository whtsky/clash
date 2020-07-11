package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/log"
)

func init() {
	log.SetLevel(log.DEBUG)
}

func TestDomainTrieRule(t *testing.T) {
	rule := NewDomainTrie()
	makeOut := func(input string) *C.AdapterName {
		name := C.AdapterName(input)
		return &name
	}
	err := rule.InsertRule(NewDomainSuffix(
		"a.com",
		"test",
	))
	if !assert.NoError(t, err) {
		return
	}

	err = rule.InsertRule(NewDomainSuffix(
		"b.dd.a.com",
		"testbb",
	))
	if !assert.NoError(t, err) {
		return
	}

	err = rule.InsertRule(NewDomain(
		"cc.com",
		"testcc",
	))
	if !assert.NoError(t, err) {
		return
	}

	var flagtests = []struct {
		in  string
		out *C.AdapterName
	}{
		{"", nil},
		{"a.com", makeOut("test")},
		{"dd.a.com", makeOut("test")},
		{"b.dd.a.com", makeOut("testbb")},
		{"b.aa.c.ddd.a.com", makeOut("test")},
		{"aa.com", nil},
		{"cc.com", makeOut("testcc")},
	}
	for _, tt := range flagtests {
		t.Run(tt.in, func(t *testing.T) {
			assert := assert.New(t)
			metadata := &C.Metadata{
				AddrType: C.AtypDomainName,
				Host:     tt.in,
			}
			assert.Equal(tt.out, rule.Match(metadata))
		})
	}

}
