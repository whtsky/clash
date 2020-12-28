package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/whtsky/clash/common/cache"
	"github.com/whtsky/clash/component/process"
	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/log"
)

var processCache = cache.NewLRUCache(cache.WithAge(2), cache.WithSize(64))

type Process struct {
	adapter C.AdapterName
	process string
}

func (ps *Process) RuleType() C.RuleType {
	return C.Process
}

func (ps *Process) Match(metadata *C.Metadata) *C.AdapterName {
	key := fmt.Sprintf("%s:%s:%s", metadata.NetWork.String(), metadata.SrcIP.String(), metadata.SrcPort)
	cached, hit := processCache.Get(key)
	if !hit {
		srcPort, err := strconv.Atoi(metadata.SrcPort)
		if err != nil {
			processCache.Set(key, "")
			return nil
		}

		name, err := process.FindProcessName(metadata.NetWork.String(), metadata.SrcIP, srcPort)
		if err != nil {
			log.Debugln("[Rule] find process name %s error: %s", C.Process.String(), err.Error())
		}

		processCache.Set(key, name)

		cached = name
	}

	if strings.EqualFold(cached.(string), ps.process) {
		name := C.AdapterName(ps.process)
		return &name
	}
	return nil
}

func (p *Process) Adapter() C.AdapterName {
	return p.adapter
}

func (p *Process) Payload() string {
	return p.process
}

func (p *Process) ShouldResolveIP() bool {
	return false
}

func NewProcess(process string, adapter C.AdapterName) (*Process, error) {
	return &Process{
		adapter: adapter,
		process: process,
	}, nil
}
