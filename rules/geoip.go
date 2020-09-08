package rules

import (
	"github.com/whtsky/clash/component/mmdb"
	C "github.com/whtsky/clash/constant"
)

type GEOIP struct {
	country     string
	adapter     C.AdapterName
	noResolveIP bool
}

func (g *GEOIP) RuleType() C.RuleType {
	return C.GEOIP
}

func (g *GEOIP) Match(metadata *C.Metadata) *C.AdapterName {
	ip := metadata.DstIP
	if ip == nil {
		return nil
	}
	record, _ := mmdb.Instance().Country(ip)
	if record.Country.IsoCode == g.country {
		return &g.adapter
	}
	return nil
}

func (d *GEOIP) Adapter() C.AdapterName {
	return d.adapter
}

func (g *GEOIP) Payload() string {
	return g.country
}

func (g *GEOIP) ShouldResolveIP() bool {
	return !g.noResolveIP
}

func NewGEOIP(country string, adapter C.AdapterName, noResolveIP bool) *GEOIP {
	geoip := &GEOIP{
		country:     country,
		adapter:     adapter,
		noResolveIP: noResolveIP,
	}

	return geoip
}
