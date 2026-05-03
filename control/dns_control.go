/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

const (
	MaxDnsLookupDepth           = 3
	dnsCacheSweepInterval       = time.Minute
	dnsCacheMaxEntries          = 4096
	dnsForwarderSweepInterval   = 5 * time.Minute
	dnsForwarderIdleTimeout     = 15 * time.Minute
	dnsForwarderCacheMaxEntries = 128
)

type IpVersionPrefer int

const (
	IpVersionPrefer_No IpVersionPrefer = 0
	IpVersionPrefer_4  IpVersionPrefer = 4
	IpVersionPrefer_6  IpVersionPrefer = 6
)

var (
	ErrUnsupportedQuestionType = fmt.Errorf("unsupported question type")
)

var (
	UnspecifiedAddressA    = netip.MustParseAddr("0.0.0.0")
	UnspecifiedAddressAAAA = netip.MustParseAddr("::")
)

type DnsControllerOption struct {
	Log                   *logrus.Logger
	AnyfromPool           *AnyfromPool
	CacheAccessCallback   func(cache *DnsCache) (err error)
	CacheRemoveCallback   func(cache *DnsCache) (err error)
	NewCache              func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	BestDialerChooser     func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	TimeoutExceedCallback func(dialArgument *dialArgument, err error)
	IpVersionPrefer       int
	FixedDomainTtl        map[string]int
}

type DnsController struct {
	handling sync.Map

	routing     *dns.Dns
	qtypePrefer uint16

	log                 *logrus.Logger
	anyfromPool         *AnyfromPool
	cacheAccessCallback func(cache *DnsCache) (err error)
	cacheRemoveCallback func(cache *DnsCache) (err error)
	newCache            func(fqdn string, answers []dnsmessage.RR, deadline time.Time, originalDeadline time.Time) (cache *DnsCache, err error)
	bestDialerChooser   func(req *udpRequest, upstream *dns.Upstream) (*dialArgument, error)
	// timeoutExceedCallback is used to report this dialer is broken for the NetworkType
	timeoutExceedCallback func(dialArgument *dialArgument, err error)

	fixedDomainTtl   map[string]int
	now              func() time.Time
	forwarderFactory func(upstream *dns.Upstream, dialArgument dialArgument) (DnsForwarder, error)
	ctx              context.Context
	cancel           context.CancelFunc
	cleanupWg        sync.WaitGroup
	// mutex protects the dnsCache.
	dnsCacheMu          sync.RWMutex
	dnsCache            map[string]*DnsCache
	dnsForwarderCacheMu sync.Mutex
	dnsForwarderCache   map[dnsForwarderKey]*cachedDnsForwarder
}

type handlingState struct {
	mu  sync.Mutex
	ref uint32
}

type cachedDnsForwarder struct {
	forwarder DnsForwarder
	lastUsed  time.Time
	refs      int
	stale     bool
}

func parseIpVersionPreference(prefer int) (uint16, error) {
	switch prefer := IpVersionPrefer(prefer); prefer {
	case IpVersionPrefer_No:
		return 0, nil
	case IpVersionPrefer_4:
		return dnsmessage.TypeA, nil
	case IpVersionPrefer_6:
		return dnsmessage.TypeAAAA, nil
	default:
		return 0, fmt.Errorf("unknown preference: %v", prefer)
	}
}

func NewDnsController(routing *dns.Dns, option *DnsControllerOption) (c *DnsController, err error) {
	// Parse ip version preference.
	prefer, err := parseIpVersionPreference(option.IpVersionPrefer)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	c = &DnsController{
		routing:     routing,
		qtypePrefer: prefer,

		log:                   option.Log,
		anyfromPool:           option.AnyfromPool,
		cacheAccessCallback:   option.CacheAccessCallback,
		cacheRemoveCallback:   option.CacheRemoveCallback,
		newCache:              option.NewCache,
		bestDialerChooser:     option.BestDialerChooser,
		timeoutExceedCallback: option.TimeoutExceedCallback,

		fixedDomainTtl:      option.FixedDomainTtl,
		now:                 time.Now,
		forwarderFactory:    newDnsForwarder,
		ctx:                 ctx,
		cancel:              cancel,
		cleanupWg:           sync.WaitGroup{},
		dnsCacheMu:          sync.RWMutex{},
		dnsCache:            make(map[string]*DnsCache),
		dnsForwarderCacheMu: sync.Mutex{},
		dnsForwarderCache:   make(map[dnsForwarderKey]*cachedDnsForwarder),
	}
	c.startBackgroundCleanup()
	return c, nil
}

func (c *DnsController) cacheKey(qname string, qtype uint16) string {
	// To fqdn.
	return dnsmessage.CanonicalName(qname) + strconv.Itoa(int(qtype))
}

func (c *DnsController) cacheExpiresAt(cache *DnsCache) time.Time {
	if cache == nil {
		return time.Time{}
	}
	if cache.Deadline.After(cache.OriginalDeadline) {
		return cache.Deadline
	}
	return cache.OriginalDeadline
}

func (c *DnsController) startBackgroundCleanup() {
	c.cleanupWg.Add(2)
	go func() {
		defer c.cleanupWg.Done()
		ticker := time.NewTicker(dnsCacheSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.sweepDnsCache(c.now())
			}
		}
	}()
	go func() {
		defer c.cleanupWg.Done()
		ticker := time.NewTicker(dnsForwarderSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.sweepDnsForwarderCache(c.now(), false)
			}
		}
	}()
}

func (c *DnsController) sweepDnsCache(now time.Time) {
	var removed []*DnsCache
	c.dnsCacheMu.Lock()
	for key, cache := range c.dnsCache {
		if c.cacheExpiresAt(cache).After(now) {
			continue
		}
		delete(c.dnsCache, key)
		removed = append(removed, cache)
	}
	c.dnsCacheMu.Unlock()
	recordDnsCacheExpiredRemovals(len(removed))
	if c.cacheRemoveCallback != nil {
		for _, cache := range removed {
			if err := c.cacheRemoveCallback(cache); err != nil {
				c.log.Warnf("failed to remove expired domain routing cache: %v", err)
			}
		}
	}
}

func (c *DnsController) evictDnsCacheEntriesLocked(now time.Time) []*DnsCache {
	var removed []*DnsCache
	expiredRemoved := 0
	for key, cache := range c.dnsCache {
		if c.cacheExpiresAt(cache).After(now) {
			continue
		}
		delete(c.dnsCache, key)
		removed = append(removed, cache)
		expiredRemoved++
	}
	for len(c.dnsCache) >= dnsCacheMaxEntries {
		var (
			oldestKey      string
			oldestCache    *DnsCache
			oldestDeadline time.Time
			oldestSeen     bool
		)
		for key, cache := range c.dnsCache {
			deadline := c.cacheExpiresAt(cache)
			if !oldestSeen || deadline.Before(oldestDeadline) {
				oldestKey = key
				oldestCache = cache
				oldestDeadline = deadline
				oldestSeen = true
			}
		}
		if !oldestSeen {
			break
		}
		delete(c.dnsCache, oldestKey)
		removed = append(removed, oldestCache)
	}
	recordDnsCacheExpiredRemovals(expiredRemoved)
	return removed
}

func (c *DnsController) sweepDnsForwarderCache(now time.Time, enforceLimit bool) {
	var forwardersToClose []DnsForwarder
	c.dnsForwarderCacheMu.Lock()
	for key, entry := range c.dnsForwarderCache {
		if entry.refs > 0 {
			continue
		}
		if entry.lastUsed.Add(dnsForwarderIdleTimeout).After(now) {
			continue
		}
		delete(c.dnsForwarderCache, key)
		entry.stale = true
		forwardersToClose = append(forwardersToClose, entry.forwarder)
	}
	if enforceLimit {
		for len(c.dnsForwarderCache) >= dnsForwarderCacheMaxEntries {
			var (
				oldestKey  dnsForwarderKey
				oldestSeen bool
				oldestTime time.Time
			)
			for key, entry := range c.dnsForwarderCache {
				if entry.refs > 0 {
					continue
				}
				if !oldestSeen || entry.lastUsed.Before(oldestTime) {
					oldestKey = key
					oldestTime = entry.lastUsed
					oldestSeen = true
				}
			}
			if !oldestSeen {
				break
			}
			c.dnsForwarderCache[oldestKey].stale = true
			forwardersToClose = append(forwardersToClose, c.dnsForwarderCache[oldestKey].forwarder)
			delete(c.dnsForwarderCache, oldestKey)
		}
	}
	c.dnsForwarderCacheMu.Unlock()
	for _, forwarder := range forwardersToClose {
		if err := forwarder.Close(); err != nil {
			c.log.Warnf("failed to close evicted dns forwarder: %v", err)
		}
	}
}

func (c *DnsController) RemoveDnsRespCache(cacheKey string) {
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	if ok {
		delete(c.dnsCache, cacheKey)
	}
	c.dnsCacheMu.Unlock()
	if ok && c.cacheRemoveCallback != nil {
		if err := c.cacheRemoveCallback(cache); err != nil {
			c.log.Warnf("failed to remove domain routing cache: %v", err)
		}
	}
}
func (c *DnsController) LookupDnsRespCache(cacheKey string, ignoreFixedTtl bool) (cache *DnsCache) {
	c.dnsCacheMu.RLock()
	cache, ok := c.dnsCache[cacheKey]
	if !ok {
		c.dnsCacheMu.RUnlock()
		return nil
	}
	var deadline time.Time
	if !ignoreFixedTtl {
		deadline = cache.Deadline
	} else {
		deadline = cache.OriginalDeadline
	}
	// We should make sure the cache did not expire, or
	// return nil and request a new lookup to refresh the cache.
	if !deadline.After(time.Now()) {
		c.dnsCacheMu.RUnlock()
		c.dnsCacheMu.Lock()
		cache, ok = c.dnsCache[cacheKey]
		if !ok {
			c.dnsCacheMu.Unlock()
			return nil
		}
		if c.cacheExpiresAt(cache).After(time.Now()) {
			c.dnsCacheMu.Unlock()
			if c.cacheAccessCallback != nil {
				if err := c.cacheAccessCallback(cache); err != nil {
					c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
					return nil
				}
			}
			recordDnsCacheHit()
			return cache
		}
		delete(c.dnsCache, cacheKey)
		c.dnsCacheMu.Unlock()
		recordDnsCacheExpiredRemovals(1)
		if c.cacheRemoveCallback != nil {
			if err := c.cacheRemoveCallback(cache); err != nil {
				c.log.Warnf("failed to remove expired domain routing cache: %v", err)
			}
		}
		return nil
	}
	c.dnsCacheMu.RUnlock()
	if c.cacheAccessCallback != nil {
		if err := c.cacheAccessCallback(cache); err != nil {
			c.log.Warnf("failed to BatchUpdateDomainRouting: %v", err)
			return nil
		}
	}
	recordDnsCacheHit()
	return cache
}

// LookupDnsRespCache_ will modify the msg in place.
func (c *DnsController) LookupDnsRespCache_(msg *dnsmessage.Msg, cacheKey string, ignoreFixedTtl bool) (resp []byte) {
	cache := c.LookupDnsRespCache(cacheKey, ignoreFixedTtl)
	if cache != nil {
		if packed := cache.FillPackedResponse(msg.Id); packed != nil {
			return packed
		}
		cache.FillInto(msg)
		msg.Compress = true
		b, err := msg.Pack()
		if err != nil {
			c.log.Warnf("failed to pack: %v", err)
			return nil
		}
		return b
	}
	return nil
}

func minDNSAnswerTTL(answers []dnsmessage.RR) (ttl uint32, ok bool) {
	if len(answers) == 0 {
		return 0, false
	}
	ttl = answers[0].Header().Ttl
	for i := 1; i < len(answers); i++ {
		if ansTTL := answers[i].Header().Ttl; ansTTL < ttl {
			ttl = ansTTL
		}
	}
	return ttl, true
}

func canonicalDnsQuestionName(name string) string {
	if name == "" {
		return ""
	}
	return dnsmessage.CanonicalName(name)
}

func dnsQuestionsEqual(a, b dnsmessage.Question) bool {
	return canonicalDnsQuestionName(a.Name) == canonicalDnsQuestionName(b.Name) &&
		a.Qtype == b.Qtype &&
		a.Qclass == b.Qclass
}

func formatDnsQuestion(q dnsmessage.Question) string {
	return fmt.Sprintf("%s %s class=%d", strings.ToLower(canonicalDnsQuestionName(q.Name)), QtypeToString(q.Qtype), q.Qclass)
}

func validateDnsResponseForRequest(reqMsg *dnsmessage.Msg, respMsg *dnsmessage.Msg, requireMatchingID bool) error {
	if respMsg == nil {
		return fmt.Errorf("dns response is nil")
	}
	if !respMsg.Response {
		return fmt.Errorf("dns response expected but dns request received")
	}
	if requireMatchingID && respMsg.Id != reqMsg.Id {
		return fmt.Errorf("dns response id mismatch: got %d want %d", respMsg.Id, reqMsg.Id)
	}
	if len(reqMsg.Question) == 0 {
		return nil
	}
	if len(respMsg.Question) == 0 {
		return fmt.Errorf("dns response missing question")
	}
	if len(respMsg.Question) != len(reqMsg.Question) {
		return fmt.Errorf("dns response question count mismatch: got %d want %d", len(respMsg.Question), len(reqMsg.Question))
	}
	for i := range reqMsg.Question {
		if dnsQuestionsEqual(reqMsg.Question[i], respMsg.Question[i]) {
			continue
		}
		return fmt.Errorf(
			"dns response question mismatch at index %d: got %s want %s",
			i,
			formatDnsQuestion(respMsg.Question[i]),
			formatDnsQuestion(reqMsg.Question[i]),
		)
	}
	return nil
}

func shouldValidateDnsResponseID(upstream *dns.Upstream, dialArgument *dialArgument) bool {
	if upstream == nil || dialArgument == nil {
		return false
	}
	switch upstream.Scheme {
	case dns.UpstreamScheme_UDP, dns.UpstreamScheme_TCP, dns.UpstreamScheme_TCP_UDP, dns.UpstreamScheme_TLS:
		return true
	default:
		return false
	}
}

// NormalizeAndCacheDnsResp_ handle DNS resp in place.
func (c *DnsController) NormalizeAndCacheDnsResp_(msg *dnsmessage.Msg) (err error) {
	// Check healthy resp.
	if !msg.Response || len(msg.Question) == 0 {
		return nil
	}

	q := msg.Question[0]

	// Check suc resp.
	if msg.Rcode != dnsmessage.RcodeSuccess {
		return nil
	}

	// Successful empty-answer responses are not cached by default.
	// They are ambiguous enough that a blanket synthetic TTL is usually
	// worse than simply re-querying upstream later.
	if len(msg.Answer) == 0 {
		return nil
	}

	ttl, ok := minDNSAnswerTTL(msg.Answer)
	if !ok {
		return nil
	}

	// Check req type.
	switch q.Qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	default:
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Set ttl.
	for i := range msg.Answer {
		// Set TTL = zero. This requests applications must resend every request.
		// However, it may be not defined in the standard.
		msg.Answer[i].Header().Ttl = 0
	}

	// Check if request A/AAAA record.
	var reqIpRecord bool
loop:
	for i := range msg.Question {
		switch msg.Question[i].Qtype {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			reqIpRecord = true
			break loop
		}
	}
	if !reqIpRecord {
		// Update DnsCache.
		if err = c.updateDnsCache(msg, ttl, &q); err != nil {
			return err
		}
		return nil
	}

	// Update DnsCache.
	if err = c.updateDnsCache(msg, ttl, &q); err != nil {
		return err
	}
	// Pack to get newData.
	return nil
}

func (c *DnsController) updateDnsCache(msg *dnsmessage.Msg, ttl uint32, q *dnsmessage.Question) error {
	// Update DnsCache.
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"_qname": q.Name,
			"rcode":  msg.Rcode,
			"ans":    FormatDnsRsc(msg.Answer),
		}).Tracef("Update DNS record cache")
	}

	if err := c.UpdateDnsCacheTtl(q.Name, q.Qtype, msg.Answer, int(ttl)); err != nil {
		return err
	}
	return nil
}

type daedlineFunc func(now time.Time, host string) (deadline time.Time, originalDeadline time.Time)

func (c *DnsController) __updateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadlineFunc daedlineFunc) (err error) {
	var fqdn string
	if strings.HasSuffix(host, ".") {
		fqdn = strings.ToLower(host)
		host = host[:len(host)-1]
	} else {
		fqdn = dnsmessage.CanonicalName(host)
	}
	// Bypass pure IP.
	if _, err = netip.ParseAddr(host); err == nil {
		return nil
	}

	now := c.now()
	deadline, originalDeadline := deadlineFunc(now, host)

	cacheKey := c.cacheKey(fqdn, dnsTyp)
	c.dnsCacheMu.Lock()
	cache, ok := c.dnsCache[cacheKey]
	ips, hasAnyIP := summarizeDNSAnswers(answers)
	var removed []*DnsCache
	if ok {
		cache.Answer = answers
		cache.IPs = ips
		cache.HasAnyIP = hasAnyIP
		cache.Deadline = deadline
		cache.OriginalDeadline = originalDeadline
		cache.RouteOwnerKey = cacheKey
		cache.PackedResponse = nil
		c.packCacheResponse(cache, fqdn, dnsTyp)
		c.dnsCacheMu.Unlock()
	} else {
		removed = c.evictDnsCacheEntriesLocked(now)
		cache, err = c.newCache(fqdn, answers, deadline, originalDeadline)
		if err != nil {
			c.dnsCacheMu.Unlock()
			return err
		}
		cache.RouteOwnerKey = cacheKey
		c.packCacheResponse(cache, fqdn, dnsTyp)
		c.dnsCache[cacheKey] = cache
		c.dnsCacheMu.Unlock()
	}
	if c.cacheRemoveCallback != nil {
		for _, removedCache := range removed {
			if err = c.cacheRemoveCallback(removedCache); err != nil {
				return err
			}
		}
	}
	if c.cacheAccessCallback != nil {
		if err = c.cacheAccessCallback(cache); err != nil {
			return err
		}
	}

	return nil
}

func (c *DnsController) UpdateDnsCacheDeadline(host string, dnsTyp uint16, answers []dnsmessage.RR, deadline time.Time) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(_ time.Time, _ string) (daedline time.Time, originalDeadline time.Time) {
		return deadline, deadline
	})
}

func (c *DnsController) UpdateDnsCacheTtl(host string, dnsTyp uint16, answers []dnsmessage.RR, ttl int) (err error) {
	return c.__updateDnsCacheDeadline(host, dnsTyp, answers, func(now time.Time, host string) (daedline time.Time, originalDeadline time.Time) {
		originalDeadline = now.Add(time.Duration(ttl) * time.Second)
		if fixedTtl, ok := c.fixedDomainTtl[host]; ok {
			return now.Add(time.Duration(fixedTtl) * time.Second), originalDeadline
		} else {
			return originalDeadline, originalDeadline
		}
	})
}

func (c *DnsController) packCacheResponse(cache *DnsCache, qname string, qtype uint16) {
	if cache == nil || len(cache.Answer) == 0 {
		cache.PackedResponse = nil
		return
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion(qname, qtype)
	cache.FillInto(msg)
	msg.Compress = true
	packed, err := msg.Pack()
	if err != nil {
		c.log.Warnf("failed to pre-pack dns cache response: %v", err)
		cache.PackedResponse = nil
		return
	}
	cache.PackedResponse = packed
	cache.Answer = nil
}

type udpRequest struct {
	ctx           context.Context
	realSrc       netip.AddrPort
	realDst       netip.AddrPort
	src           netip.AddrPort
	lConn         *net.UDPConn
	routingResult *bpfRoutingResult
}

type dialArgument struct {
	l4proto      consts.L4ProtoStr
	ipversion    consts.IpVersionStr
	bestDialer   *dialer.Dialer
	bestOutbound *outbound.DialerGroup
	bestTarget   netip.AddrPort
	mark         uint32
	mptcp        bool
}

type dnsForwarderKey struct {
	upstream     string
	dialArgument dialArgument
}

func (c *DnsController) Handle_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	return c.HandleWithResponseWriter_(dnsMessage, req, nil)
}

func (c *DnsController) HandleWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	if c.log.IsLevelEnabled(logrus.TraceLevel) && len(dnsMessage.Question) > 0 {
		q := dnsMessage.Question[0]
		c.log.Tracef("Received UDP(DNS) %v <-> %v: %v %v",
			RefineSourceToShow(req.realSrc, req.realDst.Addr()), req.realDst.String(), strings.ToLower(q.Name), QtypeToString(q.Qtype),
		)
	}

	if dnsMessage.Response {
		return fmt.Errorf("DNS request expected but DNS response received")
	}

	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		qname = dnsMessage.Question[0].Name
		qtype = dnsMessage.Question[0].Qtype
	}

	// Check ip version preference and qtype.
	switch qtype {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		if c.qtypePrefer == 0 {
			return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
		}
	default:
		return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
	}

	var qtype2 uint16
	switch qtype {
	case dnsmessage.TypeA:
		qtype2 = dnsmessage.TypeAAAA
	case dnsmessage.TypeAAAA:
		qtype2 = dnsmessage.TypeA
	default:
		return fmt.Errorf("unexpected qtype path")
	}

	if c.qtypePrefer == qtype {
		// Preferred queries should not wait for the opposite qtype. This keeps the
		// fast path fast and avoids doubling upstream traffic for every A/AAAA lookup.
		return c.handleWithResponseWriter_(dnsMessage, req, true, responseWriter)
	}

	// For non-preferred qtypes, issue both queries concurrently:
	// if the preferred qtype has records we can reject early; otherwise we may
	// still need the requested qtype response.
	dnsMessage2 := dnsMessage.Copy()
	dnsMessage2.Id = uint16(fastrand.Intn(math.MaxUint16))
	dnsMessage2.Question[0].Qtype = qtype2

	preferredErrCh := make(chan error, 1)
	requestedErrCh := make(chan error, 1)
	go func() {
		preferredErrCh <- c.handleWithResponseWriter_(dnsMessage2, req, false, nil)
	}()
	go func() {
		requestedErrCh <- c.handleWithResponseWriter_(dnsMessage, req, false, nil)
	}()

	preferredErr := <-preferredErrCh
	preferredCache := c.LookupDnsRespCache(c.cacheKey(qname, qtype2), true)
	if preferredCache != nil && preferredCache.IncludeAnyIp() {
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}

	requestedErr := <-requestedErrCh
	resp := c.LookupDnsRespCache_(dnsMessage, c.cacheKey(qname, qtype), true)
	if resp != nil {
		if responseWriter != nil {
			var respMsg dnsmessage.Msg
			if err = respMsg.Unpack(resp); err != nil {
				return fmt.Errorf("failed to unpack DNS response: %w", err)
			}
			return responseWriter.WriteMsg(&respMsg)
		}
		return sendPkt(c.anyfromPool, c.log, resp, req.realDst, req.realSrc, req.src, req.lConn)
	}

	if requestedErr != nil && preferredErr != nil {
		return errors.Join(requestedErr, preferredErr)
	}
	if requestedErr != nil {
		return requestedErr
	}
	if preferredErr != nil {
		return preferredErr
	}
	c.log.WithFields(logrus.Fields{
		"qname": qname,
	}).Tracef("Reject %v due to resp not valid", qtype)
	return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
}

func (c *DnsController) handle_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
) (err error) {
	return c.handleWithResponseWriter_(dnsMessage, req, needResp, nil)
}

func (c *DnsController) handleWithResponseWriter_(
	dnsMessage *dnsmessage.Msg,
	req *udpRequest,
	needResp bool,
	responseWriter dnsmessage.ResponseWriter,
) (err error) {
	// Prepare qname, qtype.
	var qname string
	var qtype uint16
	if len(dnsMessage.Question) != 0 {
		q := dnsMessage.Question[0]
		qname = q.Name
		qtype = q.Qtype
	}

	// Route request.
	upstreamIndex, upstream, err := c.routing.RequestSelect(qname, qtype)
	if err != nil {
		return err
	}
	if responseWriter != nil && upstreamIndex == consts.DnsRequestOutboundIndex_AsIs {
		return fmt.Errorf("dns request routing cannot use %q for locally bound dns listener; configure an explicit upstream instead", consts.DnsRequestOutboundIndex_AsIs.String())
	}

	cacheKey := c.cacheKey(qname, qtype)

	if upstreamIndex == consts.DnsRequestOutboundIndex_Reject {
		// Reject with empty answer.
		c.RemoveDnsRespCache(cacheKey)
		if !needResp {
			return nil
		}
		return c.sendRejectWithResponseWriter_(dnsMessage, req, responseWriter)
	}

	// No parallel for the same lookup.
	handlingState_, _ := c.handling.LoadOrStore(cacheKey, new(handlingState))
	handlingState := handlingState_.(*handlingState)
	atomic.AddUint32(&handlingState.ref, 1)
	handlingState.mu.Lock()
	defer func() {
		handlingState.mu.Unlock()
		atomic.AddUint32(&handlingState.ref, ^uint32(0))
		if atomic.LoadUint32(&handlingState.ref) == 0 {
			c.handling.Delete(cacheKey)
		}
	}()

	if resp := c.LookupDnsRespCache_(dnsMessage, cacheKey, false); resp != nil {
		// Send cache to client directly.
		if needResp {
			if responseWriter != nil {
				var respMsg dnsmessage.Msg
				if err = respMsg.Unpack(resp); err != nil {
					return fmt.Errorf("failed to unpack DNS response: %w", err)
				}
				return responseWriter.WriteMsg(&respMsg)
			}
			if err = sendPkt(c.anyfromPool, c.log, resp, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
				return fmt.Errorf("failed to write cached DNS resp: %w", err)
			}
		}
		if c.log.IsLevelEnabled(logrus.DebugLevel) && len(dnsMessage.Question) > 0 {
			q := dnsMessage.Question[0]
			c.log.Debugf("UDP(DNS) %v <-> Cache: %v %v",
				RefineSourceToShow(req.realSrc, req.realDst.Addr()), strings.ToLower(q.Name), QtypeToString(q.Qtype),
			)
		}
		return nil
	}

	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		upstreamName := upstreamIndex.String()
		if upstream != nil {
			upstreamName = upstream.String()
		}
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
			"upstream": upstreamName,
		}).Traceln("Request to DNS upstream")
	}

	// Re-pack DNS packet.
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	return c.dialSend(0, req, data, dnsMessage.Id, upstream, needResp)
}

func (c *DnsController) ResolveIp46(ctx context.Context, req *udpRequest, host string) (ipv46 *netutils.Ip46, err4, err6 error) {
	fqdn := dnsmessage.CanonicalName(host)
	ipv46 = &netutils.Ip46{}
	var ip4, ip6 netip.Addr

	runLookup := func(lookupCtx context.Context, qtype uint16) (netip.Addr, error) {
		msg := new(dnsmessage.Msg)
		msg.SetQuestion(fqdn, qtype)
		reqCopy := *req
		reqCopy.ctx = lookupCtx
		if err := c.handleWithResponseWriter_(msg, &reqCopy, false, nil); err != nil {
			return netip.Addr{}, err
		}
		cache := c.LookupDnsRespCache(c.cacheKey(fqdn, qtype), true)
		if cache == nil {
			return netip.Addr{}, nil
		}
		for _, ip := range cache.cachedIPs() {
			switch qtype {
			case dnsmessage.TypeA:
				if ip.Is4() || ip.Is4In6() {
					return ip.Unmap(), nil
				}
			case dnsmessage.TypeAAAA:
				if ip.Is6() && !ip.Is4In6() {
					return ip, nil
				}
			}
		}
		return netip.Addr{}, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	ctx4, cancel4 := context.WithCancel(contextOrBackground(ctx))
	ctx6, cancel6 := context.WithCancel(contextOrBackground(ctx))
	go func() {
		defer wg.Done()
		defer cancel4()
		ip, err := runLookup(ctx4, dnsmessage.TypeA)
		if err != nil && !errors.Is(err, context.Canceled) {
			err4 = err
			return
		}
		ip4 = ip
	}()
	go func() {
		defer wg.Done()
		defer cancel6()
		ip, err := runLookup(ctx6, dnsmessage.TypeAAAA)
		if err != nil && !errors.Is(err, context.Canceled) {
			err6 = err
			return
		}
		ip6 = ip
	}()
	wg.Wait()
	ipv46.Ip4 = ip4
	ipv46.Ip6 = ip6
	return ipv46, err4, err6
}

// sendReject_ send empty answer.
func (c *DnsController) sendReject_(dnsMessage *dnsmessage.Msg, req *udpRequest) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Reject")
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.anyfromPool, c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

// sendRejectWithResponseWriter_ send empty answer using response writer.
func (c *DnsController) sendRejectWithResponseWriter_(dnsMessage *dnsmessage.Msg, req *udpRequest, responseWriter dnsmessage.ResponseWriter) (err error) {
	dnsMessage.Answer = nil
	dnsMessage.Rcode = dnsmessage.RcodeSuccess
	dnsMessage.Response = true
	dnsMessage.RecursionAvailable = true
	dnsMessage.Truncated = false
	dnsMessage.Compress = true
	if c.log.IsLevelEnabled(logrus.TraceLevel) {
		c.log.WithFields(logrus.Fields{
			"question": dnsMessage.Question,
		}).Traceln("Reject")
	}
	if responseWriter != nil {
		return responseWriter.WriteMsg(dnsMessage)
	}
	data, err := dnsMessage.Pack()
	if err != nil {
		return fmt.Errorf("pack DNS packet: %w", err)
	}
	if err = sendPkt(c.anyfromPool, c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
		return err
	}
	return nil
}

func (c *DnsController) getDnsForwarder(upstream *dns.Upstream, dialArgument *dialArgument) (forwarder DnsForwarder, key dnsForwarderKey, entry *cachedDnsForwarder, reusable bool, err error) {
	if !dnsForwarderReusable(upstream, *dialArgument) {
		forwarder, err = c.forwarderFactory(upstream, *dialArgument)
		return forwarder, dnsForwarderKey{}, nil, false, err
	}

	key = dnsForwarderKey{upstream: upstream.String(), dialArgument: *dialArgument}
	now := c.now()
	c.dnsForwarderCacheMu.Lock()
	if entry, ok := c.dnsForwarderCache[key]; ok && !entry.stale {
		entry.lastUsed = now
		entry.refs++
		c.dnsForwarderCacheMu.Unlock()
		return entry.forwarder, key, entry, true, nil
	}
	c.dnsForwarderCacheMu.Unlock()

	c.sweepDnsForwarderCache(now, true)

	c.dnsForwarderCacheMu.Lock()
	if entry, ok := c.dnsForwarderCache[key]; ok && !entry.stale {
		entry.lastUsed = now
		entry.refs++
		c.dnsForwarderCacheMu.Unlock()
		return entry.forwarder, key, entry, true, nil
	}
	forwarder, err = c.forwarderFactory(upstream, *dialArgument)
	if err != nil {
		c.dnsForwarderCacheMu.Unlock()
		return nil, dnsForwarderKey{}, nil, false, err
	}
	entry = &cachedDnsForwarder{
		forwarder: forwarder,
		lastUsed:  now,
		refs:      1,
	}
	c.dnsForwarderCache[key] = entry
	c.dnsForwarderCacheMu.Unlock()
	return forwarder, key, entry, true, nil
}

func (c *DnsController) releaseDnsForwarder(key dnsForwarderKey, entry *cachedDnsForwarder, forwarder DnsForwarder, reusable bool, failed bool) error {
	if !reusable {
		if forwarder == nil {
			return nil
		}
		return forwarder.Close()
	}
	if entry == nil || forwarder == nil {
		return nil
	}

	var shouldClose bool
	c.dnsForwarderCacheMu.Lock()
	if entry.refs > 0 {
		entry.refs--
	}
	if failed {
		entry.stale = true
		if cached, ok := c.dnsForwarderCache[key]; ok && cached == entry {
			delete(c.dnsForwarderCache, key)
		}
	}
	shouldClose = entry.stale && entry.refs == 0
	c.dnsForwarderCacheMu.Unlock()

	if shouldClose {
		return forwarder.Close()
	}
	return nil
}

func shouldReportDnsDialFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func shouldRetryTruncatedDnsOverTcp(respMsg *dnsmessage.Msg, upstream *dns.Upstream, dialArgument *dialArgument) bool {
	if respMsg == nil || upstream == nil || dialArgument == nil {
		return false
	}
	if !respMsg.Truncated || dialArgument.l4proto != consts.L4ProtoStr_UDP {
		return false
	}
	return upstream.Scheme == dns.UpstreamScheme_TCP_UDP
}

func dialArgumentNetworkType(dialArgument *dialArgument) *dialer.NetworkType {
	return &dialer.NetworkType{
		L4Proto:   dialArgument.l4proto,
		IpVersion: dialArgument.ipversion,
		IsDns:     true,
	}
}

func (c *DnsController) forwardDnsUpstream(req *udpRequest, data []byte, upstream *dns.Upstream, dialArgument *dialArgument) (respMsg *dnsmessage.Msg, err error) {
	ctxDial, cancel := context.WithTimeout(contextOrBackground(req.ctx), consts.DefaultDialTimeout)
	defer cancel()

	forwarder, forwarderKey, forwarderEntry, reusable, err := c.getDnsForwarder(upstream, dialArgument)
	if err != nil {
		return nil, err
	}
	releaseForwarder := func(failed bool) error {
		if forwarder == nil {
			return nil
		}
		releaseErr := c.releaseDnsForwarder(forwarderKey, forwarderEntry, forwarder, reusable, failed)
		forwarder = nil
		return releaseErr
	}

	defer func() {
		if forwarder != nil {
			if releaseErr := releaseForwarder(err != nil); err == nil && releaseErr != nil {
				err = releaseErr
			}
		}
	}()

	respMsg, err = forwarder.ForwardDNS(ctxDial, data)
	if err != nil {
		if c.timeoutExceedCallback != nil && shouldReportDnsDialFailure(err) {
			c.timeoutExceedCallback(dialArgument, err)
		}
		return nil, err
	}
	return respMsg, nil
}

func (c *DnsController) Close() error {
	c.cancel()
	c.cleanupWg.Wait()
	c.dnsForwarderCacheMu.Lock()
	forwarders := c.dnsForwarderCache
	c.dnsForwarderCache = make(map[dnsForwarderKey]*cachedDnsForwarder)
	c.dnsForwarderCacheMu.Unlock()

	var errs []error
	for key, entry := range forwarders {
		if err := entry.forwarder.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close dns forwarder %q: %w", key.upstream, err))
		}
	}
	return errors.Join(errs...)
}

func (c *DnsController) CacheStats() (dnsCacheEntries int, dnsForwarderCacheEntries int) {
	now := c.now()
	c.dnsCacheMu.RLock()
	for _, cache := range c.dnsCache {
		if c.cacheExpiresAt(cache).After(now) {
			dnsCacheEntries++
		}
	}
	c.dnsCacheMu.RUnlock()

	c.dnsForwarderCacheMu.Lock()
	dnsForwarderCacheEntries = len(c.dnsForwarderCache)
	c.dnsForwarderCacheMu.Unlock()
	return dnsCacheEntries, dnsForwarderCacheEntries
}

func (c *DnsController) dialSend(invokingDepth int, req *udpRequest, data []byte, id uint16, upstream *dns.Upstream, needResp bool) (err error) {
	if invokingDepth >= MaxDnsLookupDepth {
		return fmt.Errorf("too deep DNS lookup invoking (depth: %v); there may be infinite loop in your DNS response routing", MaxDnsLookupDepth)
	}
	reqMsg := new(dnsmessage.Msg)
	if err := reqMsg.Unpack(data); err != nil {
		return fmt.Errorf("failed to unpack DNS request: %w", err)
	}

	upstreamName := "asis"
	if upstream == nil {
		// As-is.

		// As-is should not be valid in response routing, thus using connection realDest is reasonable.
		var ip46 netutils.Ip46
		if req.realDst.Addr().Is4() {
			ip46.Ip4 = req.realDst.Addr()
		} else {
			ip46.Ip6 = req.realDst.Addr()
		}
		upstream = &dns.Upstream{
			Scheme:   "udp",
			Hostname: req.realDst.Addr().String(),
			Port:     req.realDst.Port(),
			Ip46:     &ip46,
		}
	} else {
		upstreamName = upstream.String()
	}

	// Select best dial arguments (outbound, dialer, l4proto, ipversion, etc.)
	dialArgument, err := c.bestDialerChooser(req, upstream)
	if err != nil {
		return err
	}

	networkType := dialArgumentNetworkType(dialArgument)

	// Dial and send.
	var respMsg *dnsmessage.Msg
	respMsg, err = c.forwardDnsUpstream(req, data, upstream, dialArgument)
	if err != nil {
		return err
	}
	if err := validateDnsResponseForRequest(reqMsg, respMsg, shouldValidateDnsResponseID(upstream, dialArgument)); err != nil {
		return err
	}
	if shouldRetryTruncatedDnsOverTcp(respMsg, upstream, dialArgument) {
		recordDnsTruncatedTcpFallback()
		tcpUpstream := *upstream
		tcpUpstream.Scheme = dns.UpstreamScheme_TCP
		if c.log.IsLevelEnabled(logrus.TraceLevel) && len(respMsg.Question) > 0 {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Retry truncated UDP DNS response over TCP")
		}
		dialArgument, err = c.bestDialerChooser(req, &tcpUpstream)
		if err != nil {
			return err
		}
		networkType = dialArgumentNetworkType(dialArgument)
		respMsg, err = c.forwardDnsUpstream(req, data, upstream, dialArgument)
		if err != nil {
			return err
		}
		if err := validateDnsResponseForRequest(reqMsg, respMsg, shouldValidateDnsResponseID(&tcpUpstream, dialArgument)); err != nil {
			return err
		}
	}

	// Route response.
	upstreamIndex, nextUpstream, err := c.routing.ResponseSelect(respMsg, upstream)
	if err != nil {
		return err
	}
	switch upstreamIndex {
	case consts.DnsResponseOutboundIndex_Accept:
		// Accept.
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Accept")
		}
	case consts.DnsResponseOutboundIndex_Reject:
		// Reject the request with empty answer.
		respMsg.Answer = nil
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question": respMsg.Question,
				"upstream": upstreamName,
			}).Traceln("Reject with empty answer")
		}
		// We also cache response reject.
	default:
		if c.log.IsLevelEnabled(logrus.TraceLevel) {
			c.log.WithFields(logrus.Fields{
				"question":      respMsg.Question,
				"last_upstream": upstreamName,
				"next_upstream": nextUpstream.String(),
			}).Traceln("Change DNS upstream and resend")
		}
		return c.dialSend(invokingDepth+1, req, data, id, nextUpstream, needResp)
	}
	if upstreamIndex.IsReserved() && c.log.IsLevelEnabled(logrus.InfoLevel) {
		var (
			qname string
			qtype string
		)
		if len(respMsg.Question) > 0 {
			q := respMsg.Question[0]
			qname = strings.ToLower(q.Name)
			qtype = QtypeToString(q.Qtype)
		}
		fields := logrus.Fields{
			"network":  networkType.String(),
			"outbound": dialArgument.bestOutbound.Name,
			"policy":   dialArgument.bestOutbound.GetSelectionPolicy(),
			"dialer":   dialArgument.bestDialer.Property().Name,
			"_qname":   qname,
			"qtype":    qtype,
			"pid":      req.routingResult.Pid,
			"dscp":     req.routingResult.Dscp,
			"pname":    ProcessName2String(req.routingResult.Pname[:]),
			"mac":      Mac2String(req.routingResult.Mac[:]),
		}
		switch upstreamIndex {
		case consts.DnsResponseOutboundIndex_Accept:
			c.log.WithFields(fields).Infof("%v <-> %v", RefineSourceToShow(req.realSrc, req.realDst.Addr()), RefineAddrPortToShow(dialArgument.bestTarget))
		case consts.DnsResponseOutboundIndex_Reject:
			c.log.WithFields(fields).Infof("%v -> reject", RefineSourceToShow(req.realSrc, req.realDst.Addr()))
		default:
			return fmt.Errorf("unknown upstream: %v", upstreamIndex.String())
		}
	}
	if err = c.NormalizeAndCacheDnsResp_(respMsg); err != nil {
		return err
	}
	if needResp {
		// Keep the id the same with request.
		respMsg.Id = id
		respMsg.Compress = true
		data, err = respMsg.Pack()
		if err != nil {
			return err
		}
		if err = sendPkt(c.anyfromPool, c.log, data, req.realDst, req.realSrc, req.src, req.lConn); err != nil {
			return err
		}
	}
	return nil
}
