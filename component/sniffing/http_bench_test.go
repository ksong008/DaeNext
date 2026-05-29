package sniffing

import (
	"testing"
	"time"
)

func BenchmarkSniffingHttpHost(b *testing.B) {
	payload := []byte("GET / HTTP/1.1\r\nHost:example.com\r\n\r\n")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sniffer := NewPacketSniffer(payload, time.Second)
		domain, err := sniffer.SniffTcp()
		if err != nil {
			b.Fatal(err)
		}
		if domain != "example.com" {
			b.Fatalf("unexpected domain: %s", domain)
		}
		_ = sniffer.Close()
	}
}
