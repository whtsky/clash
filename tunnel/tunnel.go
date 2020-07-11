package tunnel

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/whtsky/clash/adapters/inbound"
	"github.com/whtsky/clash/adapters/provider"
	"github.com/whtsky/clash/component/nat"
	"github.com/whtsky/clash/component/resolver"
	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/dns"
	"github.com/whtsky/clash/log"
	"github.com/whtsky/clash/rules"

	channels "gopkg.in/eapache/channels.v1"
)

var (
	tcpQueue     = channels.NewInfiniteChannel()
	udpQueue     = channels.NewInfiniteChannel()
	natTable     = nat.New()
	rawRules     []C.Rule
	routeRules   []C.Rule
	proxies      = make(map[C.AdapterName]C.Proxy)
	providers    map[C.AdapterName]provider.ProxyProvider
	configMux    sync.RWMutex
	enhancedMode *dns.Resolver

	// Outbound Rule
	mode = Rule

	// default timeout for UDP session
	udpTimeout = 60 * time.Second
)

func init() {
	go process()
}

// Add request to queue
func Add(req C.ServerAdapter) {
	tcpQueue.In() <- req
}

// AddPacket add udp Packet to queue
func AddPacket(packet *inbound.PacketAdapter) {
	udpQueue.In() <- packet
}

// Rules return all rules
func Rules() []C.Rule {
	return routeRules
}

func CombineRules(rawRules []C.Rule) []C.Rule {
	combinedRules := make([]C.Rule, 0, len(rawRules))
	domainTrieRule := rules.NewDomainTrie()
	combinedRules = append(combinedRules, domainTrieRule)
	for _, rule := range rawRules {
		switch rule.RuleType() {
		case C.Domain, C.DomainSuffix:
			err := domainTrieRule.InsertRule(rule)
			if err != nil {
				log.Fatalln("UpdateRules: %v", err)
			}
		default:
			combinedRules = append(combinedRules, rule)
		}
	}
	return combinedRules
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule) {
	configMux.Lock()
	rawRules = newRules
	routeRules = CombineRules(newRules)
	log.Infoln("Parsed %d rules. Combined into %d rules.", len(rawRules), len(routeRules))
	configMux.Unlock()
}

// Proxies return all proxies
func Proxies() map[C.AdapterName]C.Proxy {
	return proxies
}

// Providers return all compatible providers
func Providers() map[C.AdapterName]provider.ProxyProvider {
	return providers
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[C.AdapterName]C.Proxy, newProviders map[C.AdapterName]provider.ProxyProvider) {
	configMux.Lock()
	proxies = newProxies
	providers = newProviders
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return mode
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	mode = m
}

// SetResolver set custom dns resolver for enhanced mode
func SetResolver(r *dns.Resolver) {
	enhancedMode = r
}

// processUDP starts a loop to handle udp packet
func processUDP() {
	queue := udpQueue.Out()
	for elm := range queue {
		conn := elm.(*inbound.PacketAdapter)
		handleUDPConn(conn)
	}
}

func process() {
	numUDPWorkers := 4
	if runtime.NumCPU() > numUDPWorkers {
		numUDPWorkers = runtime.NumCPU()
	}
	for i := 0; i < numUDPWorkers; i++ {
		go processUDP()
	}

	queue := tcpQueue.Out()
	for elm := range queue {
		conn := elm.(C.ServerAdapter)
		go handleTCPConn(conn)
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return enhancedMode != nil && (enhancedMode.IsMapping() || enhancedMode.FakeIPEnabled()) && metadata.Host == "" && metadata.DstIP != nil
}

func preHandleMetadata(metadata *C.Metadata) error {
	// handle IP string on host
	if ip := net.ParseIP(metadata.Host); ip != nil {
		metadata.DstIP = ip
	}

	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := enhancedMode.IPToHost(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.AddrType = C.AtypDomainName
			if enhancedMode.FakeIPEnabled() {
				metadata.DstIP = nil
			} else if node := resolver.DefaultHosts.Search(host); node != nil {
				// redir-host should lookup the hosts
				metadata.DstIP = node.Data.(net.IP)
			}
		} else if enhancedMode.IsFakeIP(metadata.DstIP) {
			return fmt.Errorf("fake DNS record %s missing", metadata.DstIP)
		}
	}

	return nil
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, elapsed time.Duration, err error) {
	switch mode {
	case Direct:
		proxy = proxies["DIRECT"]
	case Global:
		proxy = proxies["GLOBAL"]
	// Rule
	default:
		start := time.Now()
		proxy, rule, err = match(metadata)
		elapsed = time.Since(start)
		if err != nil {
			return nil, nil, elapsed, err
		}
	}
	return proxy, rule, elapsed, nil
}

func handleUDPConn(packet *inbound.PacketAdapter) {
	metadata := packet.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	// make a fAddr if requset ip is fakeip
	var fAddr net.Addr
	if enhancedMode != nil && enhancedMode.IsFakeIP(metadata.DstIP) {
		fAddr = metadata.UDPAddr()
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	key := packet.LocalAddr().String()
	pc := natTable.Get(key)
	if pc != nil {
		handleUDPToRemote(packet, pc, metadata)
		return
	}

	lockKey := key + "-lock"
	wg, loaded := natTable.GetOrCreateLock(lockKey)

	go func() {
		if !loaded {
			wg.Add(1)
			proxy, rule, elapsed, err := resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				natTable.Delete(lockKey)
				wg.Done()
				return
			}

			rawPc, err := proxy.DialUDP(metadata)
			if err != nil {
				log.Warnln("[UDP] dial %s error: %s", proxy.Name(), err.Error())
				natTable.Delete(lockKey)
				wg.Done()
				return
			}
			pc = newUDPTracker(rawPc, DefaultManager, metadata, rule)

			switch true {
			case rule != nil:
				log.Infoln(
					"[UDP] %s --> %v match %s using %s. took %s for rule matching.",
					metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), rawPc.Chains().String(),
					elapsed,
				)
			case mode == Global:
				log.Infoln(
					"[UDP] %s --> %v using GLOBAL. took %s for rule matching.",
					metadata.SourceAddress(), metadata.String(),
					elapsed,
				)
			case mode == Direct:
				log.Infoln(
					"[UDP] %s --> %v using DIRECT. took %s for rule matching.",
					metadata.SourceAddress(), metadata.String(),
					elapsed,
				)
			default:
				log.Infoln(
					"[UDP] %s --> %v doesn't match any rule using DIRECT. took %s for rule matching.",
					metadata.SourceAddress(), metadata.String(),
					elapsed,
				)
			}

			natTable.Set(key, pc)
			natTable.Delete(lockKey)
			wg.Done()
			go handleUDPToLocal(packet.UDPPacket, pc, key, fAddr)
		}

		wg.Wait()
		pc := natTable.Get(key)
		if pc != nil {
			handleUDPToRemote(packet, pc, metadata)
		}
	}()
}

func handleTCPConn(localConn C.ServerAdapter) {
	defer localConn.Close()

	metadata := localConn.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}

	if err := preHandleMetadata(metadata); err != nil {
		log.Debugln("[Metadata PreHandle] error: %s", err)
		return
	}

	proxy, rule, elapsed, err := resolveMetadata(metadata)
	if err != nil {
		log.Warnln("Parse metadata failed: %v", err)
		return
	}

	remoteConn, err := proxy.Dial(metadata)
	if err != nil {
		log.Warnln("dial %s error: %s", proxy.Name(), err.Error())
		return
	}
	remoteConn = newTCPTracker(remoteConn, DefaultManager, metadata, rule)
	defer remoteConn.Close()

	switch true {
	case rule != nil:
		log.Infoln("[TCP] %s --> %v match %s using %s. took %s for rule matching.",
			metadata.SourceAddress(), metadata.String(), rule.RuleType().String(), remoteConn.Chains().String(),
			elapsed,
		)
	case mode == Global:
		log.Infoln("[TCP] %s --> %v using GLOBAL. took %s for rule matching.",
			metadata.SourceAddress(), metadata.String(),
			elapsed,
		)
	case mode == Direct:
		log.Infoln("[TCP] %s --> %v using DIRECT. took %s for rule matching.",
			metadata.SourceAddress(), metadata.String(),
			elapsed,
		)
	default:
		log.Infoln("[TCP] %s --> %v doesn't match any rule using DIRECT. took %s for rule matching.",
			metadata.SourceAddress(), metadata.String(),
			elapsed,
		)
	}

	switch adapter := localConn.(type) {
	case *inbound.HTTPAdapter:
		handleHTTP(adapter, remoteConn)
	case *inbound.SocketAdapter:
		handleSocket(adapter, remoteConn)
	}
}

func shouldResolveIP(rule C.Rule, metadata *C.Metadata) bool {
	return !rule.NoResolveIP() && metadata.Host != "" && metadata.DstIP == nil
}

func match(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	configMux.RLock()
	defer configMux.RUnlock()

	var resolved bool

	if node := resolver.DefaultHosts.Search(metadata.Host); node != nil {
		ip := node.Data.(net.IP)
		metadata.DstIP = ip
		resolved = true
	}

	for _, rule := range routeRules {
		if !resolved && shouldResolveIP(rule, metadata) {
			ip, err := resolver.ResolveIP(metadata.Host)
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				metadata.DstIP = ip
			}
			resolved = true
		}

		if adapter := rule.Match(metadata); adapter != nil {
			adapter, ok := proxies[*adapter]
			if !ok {
				log.Fatalln("Unknown adapter: %s", adapter)
			}

			if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
				log.Debugln("%v UDP is not supported", adapter.Name())
				continue
			}
			return adapter, rule, nil
		}
	}

	return proxies["DIRECT"], nil, nil
}
