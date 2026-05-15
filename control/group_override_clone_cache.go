/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/sirupsen/logrus"
)

type groupOverrideCloneCache struct {
	created func(*dialer.Dialer)
	dialers map[groupOverrideCloneKey]*dialer.Dialer
}

type groupOverrideCloneKey struct {
	base    *dialer.Dialer
	profile groupOverrideHealthProfileKey
}

type groupOverrideHealthProfileKey struct {
	tcpCheckURL             string
	tcpCheckHTTPMethod      string
	tcpCheckResolverNetwork string
	tcpCheckResolverDialer  interfaceIdentityKey
	tcpCheckResolverDNS     netip.AddrPort
	udpCheckDNS             string
	udpCheckResolverNetwork string
	udpCheckResolverDialer  interfaceIdentityKey
	udpCheckSomark          uint32
	udpCheckResolverDNS     netip.AddrPort
	checkInterval           time.Duration
	checkTolerance          time.Duration
	checkDnsTcp             bool
}

type interfaceIdentityKey struct {
	typ   reflect.Type
	ptr   uintptr
	value string
}

func newGroupOverrideCloneCache(created func(*dialer.Dialer)) *groupOverrideCloneCache {
	return &groupOverrideCloneCache{
		created: created,
		dialers: make(map[groupOverrideCloneKey]*dialer.Dialer),
	}
}

func (c *groupOverrideCloneCache) clone(base *dialer.Dialer, option *dialer.GlobalOption) *dialer.Dialer {
	return c.cloneWithProfile(base, option, groupOverrideHealthProfile(option))
}

func (c *groupOverrideCloneCache) cloneWithProfile(base *dialer.Dialer, option *dialer.GlobalOption, profile groupOverrideHealthProfileKey) *dialer.Dialer {
	key := groupOverrideCloneKey{
		base:    base,
		profile: profile,
	}
	if cached, ok := c.dialers[key]; ok {
		return cached
	}

	clone := base.Clone()
	clone.GlobalOption = option
	c.dialers[key] = clone
	if c.created != nil {
		c.created(clone)
	}
	return clone
}

func groupOverrideHealthProfile(option *dialer.GlobalOption) groupOverrideHealthProfileKey {
	return groupOverrideHealthProfileKey{
		tcpCheckURL:             stringSliceProfileKey(option.TcpCheckOptionRaw.Raw),
		tcpCheckHTTPMethod:      option.TcpCheckOptionRaw.Method,
		tcpCheckResolverNetwork: option.TcpCheckOptionRaw.ResolverNetwork,
		tcpCheckResolverDialer:  interfaceIdentityProfileKey(option.TcpCheckOptionRaw.ResolverDialer),
		tcpCheckResolverDNS:     option.TcpCheckOptionRaw.ResolverDNS,
		udpCheckDNS:             stringSliceProfileKey(option.CheckDnsOptionRaw.Raw),
		udpCheckResolverNetwork: option.CheckDnsOptionRaw.ResolverNetwork,
		udpCheckResolverDialer:  interfaceIdentityProfileKey(option.CheckDnsOptionRaw.ResolverDialer),
		udpCheckSomark:          option.CheckDnsOptionRaw.Somark,
		udpCheckResolverDNS:     option.CheckDnsOptionRaw.ResolverDNS,
		checkInterval:           option.CheckInterval,
		checkTolerance:          option.CheckTolerance,
		checkDnsTcp:             option.CheckDnsTcp,
	}
}

func countGroupOverrideHealthProfiles(groups []config.Group, global config.Global, baseOption *dialer.GlobalOption, log *logrus.Logger) map[groupOverrideHealthProfileKey]int {
	counts := make(map[groupOverrideHealthProfileKey]int)
	for _, group := range groups {
		groupOption, err := ParseGroupOverrideOption(group, global, log)
		if err != nil || groupOption == nil {
			continue
		}
		inheritGroupOverrideResolverOption(groupOption, baseOption)
		counts[groupOverrideHealthProfile(groupOption)]++
	}
	return counts
}

func inheritGroupOverrideResolverOption(groupOption, baseOption *dialer.GlobalOption) {
	groupOption.ResolverDialer = baseOption.ResolverDialer
	groupOption.ResolverFullconeDialer = baseOption.ResolverFullconeDialer
	groupOption.ResolverDNS = baseOption.ResolverDNS
	groupOption.TcpCheckOptionRaw.ResolverDialer = baseOption.ResolverDialer
	groupOption.TcpCheckOptionRaw.ResolverDNS = baseOption.ResolverDNS
	groupOption.CheckDnsOptionRaw.ResolverDialer = baseOption.ResolverDialer
	groupOption.CheckDnsOptionRaw.ResolverDNS = baseOption.ResolverDNS
}

func interfaceIdentityProfileKey(value any) interfaceIdentityKey {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return interfaceIdentityKey{}
	}

	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return interfaceIdentityKey{
			typ: v.Type(),
			ptr: v.Pointer(),
		}
	default:
		return interfaceIdentityKey{
			typ:   v.Type(),
			value: fmt.Sprintf("%#v", value),
		}
	}
}

func stringSliceProfileKey(values []string) string {
	if values == nil {
		return "nil"
	}

	var b strings.Builder
	b.WriteString(strconv.Itoa(len(values)))
	b.WriteByte('|')
	for _, value := range values {
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
		b.WriteByte('|')
	}
	return b.String()
}
