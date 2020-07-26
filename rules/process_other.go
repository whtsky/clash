// +build !darwin,!linux

package rules

import (
	C "github.com/whtsky/clash/constant"
)

func NewProcess(process string, adapter C.AdapterName) (C.Rule, error) {
	return nil, ErrPlatformNotSupport
}
