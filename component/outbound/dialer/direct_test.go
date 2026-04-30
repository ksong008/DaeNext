package dialer

import (
	"context"
	"reflect"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	outbounddirect "github.com/daeuniverse/outbound/protocol/direct"
	"github.com/sirupsen/logrus"
)

type stubDialer struct{}

func (d *stubDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	return nil, nil
}

func TestNewDirectDialerPrefersInjectedResolverDialer(t *testing.T) {
	injected := &stubDialer{}
	option := &GlobalOption{ResolverDialer: injected}

	gotDialer, prop := NewDirectDialer(option, false)

	if gotDialer != injected {
		t.Fatalf("expected injected resolver dialer, got %T", gotDialer)
	}
	if prop == nil || prop.Name != "direct" {
		t.Fatalf("expected direct property metadata, got %#v", prop)
	}
}

func TestNewDirectDialerPrefersInjectedFullconeResolverDialer(t *testing.T) {
	injected := &stubDialer{}
	option := &GlobalOption{ResolverFullconeDialer: injected}

	gotDialer, prop := NewDirectDialer(option, true)

	if gotDialer != injected {
		t.Fatalf("expected injected fullcone resolver dialer, got %T", gotDialer)
	}
	if prop == nil || prop.Name != "direct" {
		t.Fatalf("expected direct property metadata, got %#v", prop)
	}
}

func TestResolverDialerOrDefaultBuildsFallbackWhenGlobalsAreUnset(t *testing.T) {
	prevSymmetric := outbounddirect.SymmetricDirect
	prevFullcone := outbounddirect.FullconeDirect
	outbounddirect.SymmetricDirect = nil
	outbounddirect.FullconeDirect = nil
	t.Cleanup(func() {
		outbounddirect.SymmetricDirect = prevSymmetric
		outbounddirect.FullconeDirect = prevFullcone
	})

	if got := resolverDialerOrDefault(nil, false); got == nil {
		t.Fatal("expected fallback resolver dialer for symmetric mode")
	}
	if got := resolverDialerOrDefault(nil, true); got == nil {
		t.Fatal("expected fallback resolver dialer for fullcone mode")
	}
}

func TestNewFromLinkSS2022DoesNotDependOnGlobalDirectDialer(t *testing.T) {
	prevSymmetric := outbounddirect.SymmetricDirect
	prevFullcone := outbounddirect.FullconeDirect
	outbounddirect.SymmetricDirect = nil
	outbounddirect.FullconeDirect = nil
	t.Cleanup(func() {
		outbounddirect.SymmetricDirect = prevSymmetric
		outbounddirect.FullconeDirect = prevFullcone
	})

	d, err := NewFromLink(&GlobalOption{Log: logrus.New()}, InstanceOption{}, "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@example.com:443#node", "")
	if err != nil {
		t.Fatalf("NewFromLink returned error: %v", err)
	}
	parentDialer := reflect.ValueOf(d.Dialer).Elem().FieldByName("parentDialer")
	if !parentDialer.IsValid() || parentDialer.IsNil() {
		t.Fatal("expected shadowsocks_2022 parent dialer to be initialized")
	}
}
