package control

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

func BenchmarkFunctionalDnsPackedResponseRestore(b *testing.B) {
	cache := &DnsCache{
		PackedResponse: []byte{
			0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a',
			'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
			0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01,
			0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
			0x01, 0x01, 0x01, 0x01,
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		packed := cache.FillPackedResponse(0x1234)
		if len(packed) != len(cache.PackedResponse) || packed[0] != 0x12 || packed[1] != 0x34 {
			b.Fatalf("unexpected packed response restore: %v", packed[:2])
		}
	}
}

func BenchmarkFunctionalDnsCacheKeyRoundtrip(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key := newDnsCacheKey("Example.COM", dnsmessage.TypeA, dnsmessage.ClassINET)
		structured, ok := parseDnsCacheKey(key.String())
		if !ok {
			b.Fatal("failed to parse structured dns cache key")
		}
		legacy, ok := parseDnsCacheKey("example.com.1")
		if !ok {
			b.Fatal("failed to parse legacy dns cache key")
		}
		if structured.qname != "example.com." || legacy.qclass != dnsmessage.ClassINET {
			b.Fatalf("unexpected dns cache key structured=%+v legacy=%+v", structured, legacy)
		}
	}
}

func BenchmarkFunctionalDnsCacheTtlLookup(b *testing.B) {
	now := time.Unix(1_700_000_000, 0)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		controller := &DnsController{
			now:      func() time.Time { return now },
			dnsCache: make(map[dnsCacheKey]*DnsCache),
		}
		liveKey := controller.cacheKey("live.example.", dnsmessage.TypeA)
		clientExpiredKey := controller.cacheKey("client-expired.example.", dnsmessage.TypeA)
		expiredKey := controller.cacheKey("expired.example.", dnsmessage.TypeA)
		controller.dnsCache[liveKey] = &DnsCache{
			Deadline:         now.Add(time.Minute),
			OriginalDeadline: now.Add(time.Minute),
		}
		controller.dnsCache[clientExpiredKey] = &DnsCache{
			Deadline:         now.Add(-time.Minute),
			OriginalDeadline: now.Add(time.Minute),
		}
		controller.dnsCache[expiredKey] = &DnsCache{
			Deadline:         now.Add(-time.Minute),
			OriginalDeadline: now.Add(-time.Minute),
		}
		if cache := controller.LookupDnsRespCache(liveKey, false); cache == nil {
			b.Fatal("expected live cache hit")
		}
		if cache := controller.LookupDnsRespCache(clientExpiredKey, false); cache != nil {
			b.Fatal("expected client-expired cache miss")
		}
		if cache := controller.LookupDnsRespCache(clientExpiredKey, true); cache == nil {
			b.Fatal("expected internal cache hit")
		}
		if cache := controller.LookupDnsRespCache(expiredKey, false); cache != nil {
			b.Fatal("expected expired cache miss")
		}
	}
}

func BenchmarkFunctionalDnsDohGetRequest(b *testing.B) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	payload := []byte{0x12, 0x34, 0x56, 0x78}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildDoHRequest(ctx, "1.1.1.1:443", upstream, payload)
		if err != nil {
			b.Fatal(err)
		}
		if req.Method != http.MethodGet || req.Host != "dns.example.com" {
			b.Fatalf("unexpected doh get request: method=%s host=%s", req.Method, req.Host)
		}
	}
}

func BenchmarkFunctionalDnsDohPostRequest(b *testing.B) {
	upstream := &componentdns.Upstream{
		Hostname: "dns.example.com",
		Path:     "/dns-query",
	}
	payload := append([]byte{0x12, 0x34}, make([]byte, doHGetMaxEncodedQueryBytes)...)
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		req, err := buildDoHRequest(ctx, "1.1.1.1:443", upstream, payload)
		if err != nil {
			b.Fatal(err)
		}
		if req.Method != http.MethodPost || req.Header.Get("Content-Type") != doHMediaType {
			b.Fatalf("unexpected doh post request: method=%s content-type=%s", req.Method, req.Header.Get("Content-Type"))
		}
	}
}

func BenchmarkFunctionalDnsDohValidateContentType(b *testing.B) {
	responses := []*http.Response{
		{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{doHMediaType}}},
		{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{doHMediaType + "; charset=binary"}}},
		{StatusCode: http.StatusBadGateway, Status: "502 Bad Gateway", Header: http.Header{"Content-Type": []string{doHMediaType}}},
		{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for index, resp := range responses {
			err := validateDoHResponse(resp)
			if index < 2 && err != nil {
				b.Fatalf("expected valid doh response, got %v", err)
			}
			if index >= 2 && err == nil {
				b.Fatal("expected invalid doh response")
			}
		}
	}
}

func BenchmarkFunctionalDnsValidationQuestionID(b *testing.B) {
	req := new(dnsmessage.Msg)
	req.SetQuestion("example.com.", dnsmessage.TypeA)
	req.Id = 0x1111

	matching := new(dnsmessage.Msg)
	matching.SetReply(req)
	mismatchedID := new(dnsmessage.Msg)
	mismatchedID.SetReply(req)
	mismatchedID.Id = 0x2222
	mismatchedQuestion := new(dnsmessage.Msg)
	mismatchedQuestion.SetReply(req)
	mismatchedQuestion.Question[0].Name = "other.example."

	cases := []struct {
		response  *dnsmessage.Msg
		requireID bool
		wantOK    bool
	}{
		{matching, true, true},
		{mismatchedID, true, false},
		{mismatchedID, false, true},
		{mismatchedQuestion, true, false},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			err := validateDnsResponseForRequest(req, tc.response, tc.requireID)
			if (err == nil) != tc.wantOK {
				b.Fatalf("validateDnsResponseForRequest() error=%v wantOK=%v", err, tc.wantOK)
			}
		}
	}
}

func BenchmarkFunctionalDnsResolveAsisGuard(b *testing.B) {
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	routing, err := componentdns.New(&config.Dns{
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Fallback: "asis",
			},
			Response: config.DnsResponseRouting{
				Fallback: "accept",
			},
		},
	}, &componentdns.NewOption{
		Logger: log,
		UpstreamReadyCallback: func(*componentdns.Upstream) error {
			return nil
		},
	})
	if err != nil {
		b.Fatalf("failed to build dns routing: %v", err)
	}
	controller := &DnsController{
		routing:  routing,
		log:      log,
		now:      time.Now,
		dnsCache: make(map[dnsCacheKey]*DnsCache),
	}
	msg := new(dnsmessage.Msg)
	msg.SetQuestion("example.com.", dnsmessage.TypeA)
	req := &udpRequest{
		ctx:          context.Background(),
		realSrc:      netip.MustParseAddrPort("192.0.2.10:43210"),
		realDst:      netip.MustParseAddrPort("93.184.216.34:443"),
		src:          netip.MustParseAddrPort("192.0.2.10:43210"),
		disallowAsIs: true,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := controller.handleWithResponseWriter_(msg, req, false, nil); err == nil {
			b.Fatal("expected synthetic asis guard error")
		}
	}
}

func BenchmarkFunctionalControlChooseDialTargetDomain(b *testing.B) {
	c := &ControlPlane{
		log:      logrus.New(),
		dialMode: consts.DialMode_Ip,
	}
	src := netip.MustParseAddrPort("0.0.0.0:0")
	dst := netip.MustParseAddrPort("0.0.0.0:443")
	routingResult := &bpfRoutingResult{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		target, _, dialIP := c.ChooseDialTarget(context.Background(), src, routingResult, consts.OutboundDirect, dst, "example.com")
		if target != "example.com:443" || dialIP {
			b.Fatalf("unexpected target=%q dialIP=%v", target, dialIP)
		}
	}
}

func BenchmarkFunctionalControlChooseDialTargetDomainPlusPlus(b *testing.B) {
	c := &ControlPlane{
		log:      logrus.New(),
		dialMode: consts.DialMode_DomainCao,
	}
	src := netip.MustParseAddrPort("192.0.2.10:43210")
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	routingResult := &bpfRoutingResult{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		target, shouldReroute, dialIP := c.ChooseDialTarget(context.Background(), src, routingResult, consts.OutboundUserDefinedMin, dst, "example.com")
		if target != "example.com:443" || !shouldReroute || dialIP {
			b.Fatalf("unexpected target=%q shouldReroute=%v dialIP=%v", target, shouldReroute, dialIP)
		}
	}
}
