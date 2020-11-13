package outboundgroup

import (
	"errors"
	"fmt"

	"github.com/whtsky/clash/adapters/provider"
	"github.com/whtsky/clash/common/structure"
	C "github.com/whtsky/clash/constant"
)

var (
	errFormat            = errors.New("format error")
	errType              = errors.New("unsupport type")
	errMissProxy         = errors.New("`use` or `proxies` missing")
	errMissHealthCheck   = errors.New("`url` or `interval` missing")
	errDuplicateProvider = errors.New("`duplicate provider name")
)

type GroupCommonOption struct {
	Name     C.AdapterName   `group:"name"`
	Type     string          `group:"type"`
	Proxies  []C.AdapterName `group:"proxies,omitempty"`
	Use      []C.AdapterName `group:"use,omitempty"`
	URL      string          `group:"url,omitempty"`
	Interval int             `group:"interval,omitempty"`
}

func ParseProxyGroup(config map[string]interface{}, proxyMap map[C.AdapterName]C.Proxy, providersMap map[C.AdapterName]provider.ProxyProvider) (C.ProxyAdapter, error) {
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})

	groupOption := &GroupCommonOption{}
	if err := decoder.Decode(config, groupOption); err != nil {
		return nil, errFormat
	}

	if groupOption.Type == "" || groupOption.Name == "" {
		return nil, errFormat
	}

	groupName := groupOption.Name

	providers := []provider.ProxyProvider{}

	if len(groupOption.Proxies) == 0 && len(groupOption.Use) == 0 {
		return nil, errMissProxy
	}

	if len(groupOption.Proxies) != 0 {
		ps, err := getProxies(proxyMap, groupOption.Proxies)
		if err != nil {
			return nil, err
		}

		// if Use not empty, drop health check options
		if len(groupOption.Use) != 0 {
			hc := provider.NewHealthCheck(ps, "", 0)
			pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
			if err != nil {
				return nil, err
			}

			providers = append(providers, pd)
		} else {
			if _, ok := providersMap[groupName]; ok {
				return nil, errDuplicateProvider
			}

			// select don't need health check
			if groupOption.Type == "select" || groupOption.Type == "relay" {
				hc := provider.NewHealthCheck(ps, "", 0)
				pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
				if err != nil {
					return nil, err
				}

				providers = append(providers, pd)
				providersMap[groupName] = pd
			} else {
				if groupOption.URL == "" || groupOption.Interval == 0 {
					return nil, errMissHealthCheck
				}

				hc := provider.NewHealthCheck(ps, groupOption.URL, uint(groupOption.Interval))
				pd, err := provider.NewCompatibleProvider(groupName, ps, hc)
				if err != nil {
					return nil, err
				}

				providers = append(providers, pd)
				providersMap[groupName] = pd
			}
		}
	}

	if len(groupOption.Use) != 0 {
		list, err := getProviders(providersMap, groupOption.Use)
		if err != nil {
			return nil, err
		}
		providers = append(providers, list...)
	}

	var group C.ProxyAdapter
	switch groupOption.Type {
	case "url-test":
		opts := parseURLTestOption(config)
		group = NewURLTest(groupName, providers, opts...)
	case "select":
		group = NewSelector(groupName, providers)
	case "fallback":
		group = NewFallback(groupName, providers)
	case "load-balance":
		strategy := parseStrategy(config)
		return NewLoadBalance(groupName, providers, strategy)
	case "relay":
		group = NewRelay(groupName, providers)
	default:
		return nil, fmt.Errorf("%w: %s", errType, groupOption.Type)
	}

	return group, nil
}

func getProxies(mapping map[C.AdapterName]C.Proxy, list []C.AdapterName) ([]C.Proxy, error) {
	var ps []C.Proxy
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}

func getProviders(mapping map[C.AdapterName]provider.ProxyProvider, list []C.AdapterName) ([]provider.ProxyProvider, error) {
	var ps []provider.ProxyProvider
	for _, name := range list {
		p, ok := mapping[name]
		if !ok {
			return nil, fmt.Errorf("'%s' not found", name)
		}

		if p.VehicleType() == provider.Compatible {
			return nil, fmt.Errorf("proxy group %s can't contains in `use`", name)
		}
		ps = append(ps, p)
	}
	return ps, nil
}
