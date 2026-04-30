/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"net/netip"

	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func newResolverFallbackDialer(resolverDNS netip.AddrPort, fullcone bool) netproxy.Dialer {
	fallbackDNS := ""
	if resolverDNS.IsValid() {
		fallbackDNS = resolverDNS.String()
	}
	return direct.NewDirectDialerLaddr(netip.Addr{}, direct.Option{
		FullCone:    fullcone,
		FallbackDNS: fallbackDNS,
	})
}

func resolverDialerOrDefault(option *GlobalOption, fullcone bool) netproxy.Dialer {
	if option == nil {
		return newResolverFallbackDialer(netip.AddrPort{}, fullcone)
	}
	if fullcone {
		if option.ResolverFullconeDialer != nil {
			return option.ResolverFullconeDialer
		}
	} else if option.ResolverDialer != nil {
		return option.ResolverDialer
	}
	return newResolverFallbackDialer(option.ResolverDNS, fullcone)
}

func NewDirectDialer(option *GlobalOption, fullcone bool) (netproxy.Dialer, *Property) {
	property := &Property{
		Property: D.Property{
			Name:     "direct",
			Address:  "",
			Protocol: "",
			Link:     "",
		},
		SubscriptionTag: "",
		Link:            "",
	}
	if option != nil {
		if fullcone && option.ResolverFullconeDialer != nil {
			return option.ResolverFullconeDialer, property
		}
		if !fullcone && option.ResolverDialer != nil {
			return option.ResolverDialer, property
		}
	}
	d, _p := D.NewDirectDialer(&option.ExtraOption, fullcone)
	return d, &Property{
		Property:        *_p,
		SubscriptionTag: "",
		Link:            "",
	}
}
