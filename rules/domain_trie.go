package rules

import (
	"errors"
	"strings"

	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/log"
)

type domainRule struct {
	Rule    C.RuleType
	Adapter C.AdapterName
}

type domainTrieNode struct {
	rule     *domainRule
	children map[string]*domainTrieNode
}

func newNode() *domainTrieNode {
	return &domainTrieNode{
		children: make(map[string]*domainTrieNode),
	}
}

func (node *domainTrieNode) insert(parts []string, rule *domainRule) {
	log.Debugln("parts=%v", parts)
	length := len(parts)
	if length == 0 {
		node.rule = rule
	} else {
		child, ok := node.children[parts[length-1]]
		if !ok {
			child = newNode()
			node.children[parts[length-1]] = child
		}
		child.insert(parts[:length-1], rule)
	}
}

type DomainTrie struct {
	root *domainTrieNode
}

const (
	domainSep = "."
)

func validAndSplitDomain(domain string) []string {
	if domain != "" && domain[len(domain)-1] == '.' {
		return nil
	}

	parts := strings.Split(domain, domainSep)
	if len(parts) == 1 {
		if parts[0] == "" {
			return nil
		}

		return parts
	}

	for _, part := range parts[1:] {
		if part == "" {
			return nil
		}
	}

	return parts
}

var (
	ErrInvalidDomain    = errors.New("invalid domain")
	ErrNotSupportedRule = errors.New("DomainTrie only supports Domain & DoaminSuffix Rule")
)

func (t *DomainTrie) InsertRule(rule C.Rule) error {
	ruleType := rule.RuleType()
	switch ruleType {
	case C.DomainSuffix, C.Domain:
	default:
		return ErrNotSupportedRule
	}
	domain := rule.Payload()
	parts := validAndSplitDomain(domain)
	if parts == nil {
		return ErrInvalidDomain
	}

	domainRule := domainRule{
		Rule:    ruleType,
		Adapter: rule.Adapter(),
	}

	t.root.insert(parts, &domainRule)
	return nil
}

func (rule *DomainTrie) RuleType() C.RuleType {
	return C.DomainTrie
}

func (rule *DomainTrie) Match(metadata *C.Metadata) *C.AdapterName {
	if metadata.AddrType != C.AtypDomainName {
		return nil
	}
	domain := metadata.Host
	parts := validAndSplitDomain(domain)
	if parts == nil {
		return nil
	}

	node := rule.root

	var bestMatch *C.AdapterName

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		log.Debugln("part=%s, bestMatch=%v", part, bestMatch)
		var ok bool
		node, ok = node.children[part]
		if !ok {
			log.Debugln("no child, return bestMatch")
			return bestMatch
		}
		if node.rule != nil {
			switch node.rule.Rule {
			case C.DomainSuffix:
				bestMatch = &node.rule.Adapter
			case C.Domain:
				if i == 0 {
					return &node.rule.Adapter
				}
			}
		}
	}

	return bestMatch
}

func (rule *DomainTrie) Adapter() C.AdapterName {
	return C.AdapterName("")
}

func (rule *DomainTrie) Payload() string {
	return ""
}

func (rule *DomainTrie) ShouldResolveIP() bool {
	return false
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: newNode(),
	}
}
