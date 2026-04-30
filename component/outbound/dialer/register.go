/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func NewFromLink(gOption *GlobalOption, iOption InstanceOption, link string, subscriptionTag string) (*Dialer, error) {
	resolverDialer := direct.SymmetricDirect
	if gOption != nil && gOption.ResolverDialer != nil {
		resolverDialer = gOption.ResolverDialer
	}
	d, _p, err := D.NewNetproxyDialerFromLink(resolverDialer, &gOption.ExtraOption, link)
	if err != nil {
		return nil, err
	}
	p := Property{
		Property:        *_p,
		SubscriptionTag: subscriptionTag,
		Link:            link,
	}
	return NewDialer(d, gOption, iOption, &p), nil
}
