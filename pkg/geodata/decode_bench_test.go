package geodata

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func BenchmarkGeodataEmitBytesGeoIPHit(b *testing.B) {
	data, err := hex.DecodeString("0a240a02434e12080a04cb007100101812140a1020010db800000000000000000000000010200a0e0a02555312080a04c63364001018")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		entry, err := emitBytes(bytes.NewReader(data), "cn")
		if err != nil {
			b.Fatal(err)
		}
		if len(entry) != 36 {
			b.Fatalf("unexpected entry length: %d", len(entry))
		}
	}
}
