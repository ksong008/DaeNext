package dialer

import (
	"context"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
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
