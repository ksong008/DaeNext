package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	defaultServerName = "utls-profiles.invalid"
	defaultAlpn       = "h2,http/1.1"
)

type fixtureFile struct {
	Name          string          `json:"name"`
	ProfileFamily string          `json:"profile_family"`
	Source        []string        `json:"source"`
	SourceModules []sourceModule  `json:"source_modules,omitempty"`
	ServerName    string          `json:"server_name"`
	Alpn          []string        `json:"alpn"`
	Samples       []fixtureSample `json:"samples"`
}

type sourceModule struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Sum     string `json:"sum,omitempty"`
}

type fixtureSample struct {
	Fingerprint string `json:"fingerprint"`
	RecordHex   string `json:"record_hex"`
}

func main() {
	serverName := flag.String("server-name", defaultServerName, "SNI used only for fixture generation")
	alpnCSV := flag.String("alpn", defaultAlpn, "comma-separated ALPN list used only for fixture generation")
	fingerprintCSV := flag.String("fingerprints", strings.Join(defaultFingerprintNames(), ","), "comma-separated uTLS fingerprints to capture")
	flag.Parse()

	alpn := splitCSV(*alpnCSV)
	names := splitCSV(*fingerprintCSV)
	samples := make([]fixtureSample, 0, len(names))
	for _, name := range names {
		id, ok := clientHelloID(name)
		if !ok {
			failf("unsupported fixture fingerprint %q", name)
		}
		record, err := captureClientHello(id, *serverName, alpn)
		if err != nil {
			failf("%s: %v", name, err)
		}
		record, err = normalizeClientHelloRecord(record)
		if err != nil {
			failf("%s: normalize: %v", name, err)
		}
		samples = append(samples, fixtureSample{
			Fingerprint: name,
			RecordHex:   hex.EncodeToString(record),
		})
	}

	out := fixtureFile{
		Name:          "utls-clienthello-profile-fixture",
		ProfileFamily: "utls-clienthello",
		Source:        []string{"github.com/refraction-networking/utls"},
		SourceModules: sourceModules(),
		ServerName:    *serverName,
		Alpn:          alpn,
		Samples:       samples,
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		failf("encode fixture: %v", err)
	}
	os.Stdout.Write(encoded)
	os.Stdout.Write([]byte("\n"))
}

func defaultFingerprintNames() []string {
	names := make([]string, 0, len(fingerprintIDs))
	for name := range fingerprintIDs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func captureClientHello(id utls.ClientHelloID, serverName string, alpn []string) ([]byte, error) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	errCh := make(chan error, 1)
	go func() {
		defer client.Close()
		conn := utls.UClient(client, &utls.Config{
			ServerName: serverName,
			NextProtos: alpn,
		}, id)
		errCh <- conn.Handshake()
	}()

	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		return nil, fmt.Errorf("read TLS record header: %w", err)
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		return nil, fmt.Errorf("read TLS record body: %w", err)
	}
	server.Close()
	<-errCh
	return append(header, body...), nil
}

func clientHelloID(name string) (utls.ClientHelloID, bool) {
	id, ok := fingerprintIDs[name]
	return id, ok
}

func sourceModules() []sourceModule {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	out := make([]sourceModule, 0, len(info.Deps))
	for _, dep := range info.Deps {
		if dep.Path != "github.com/refraction-networking/utls" {
			continue
		}
		version := dep.Version
		sum := dep.Sum
		if dep.Replace != nil {
			version = dep.Replace.Version
			sum = dep.Replace.Sum
		}
		out = append(out, sourceModule{
			Path:    dep.Path,
			Version: version,
			Sum:     sum,
		})
	}
	return out
}

var fingerprintIDs = map[string]utls.ClientHelloID{
	"360":               utls.Hello360_Auto,
	"360_11_0":          utls.Hello360_11_0,
	"360_auto":          utls.Hello360_Auto,
	"android_11_okhttp": utls.HelloAndroid_11_OkHttp,
	"chrome":            utls.HelloChrome_Auto,
	"chrome_102":        utls.HelloChrome_102,
	"chrome_auto":       utls.HelloChrome_Auto,
	"edge":              utls.HelloEdge_Auto,
	"edge_106":          utls.HelloEdge_106,
	"edge_auto":         utls.HelloEdge_Auto,
	"firefox":           utls.HelloFirefox_Auto,
	"firefox_55":        utls.HelloFirefox_55,
	"firefox_56":        utls.HelloFirefox_56,
	"firefox_63":        utls.HelloFirefox_63,
	"firefox_65":        utls.HelloFirefox_65,
	"firefox_99":        utls.HelloFirefox_99,
	"firefox_102":       utls.HelloFirefox_102,
	"firefox_105":       utls.HelloFirefox_105,
	"firefox_auto":      utls.HelloFirefox_Auto,
	"ios":               utls.HelloIOS_Auto,
	"ios_14":            utls.HelloIOS_14,
	"ios_auto":          utls.HelloIOS_Auto,
	"qq":                utls.HelloQQ_Auto,
	"qq_11_1":           utls.HelloQQ_11_1,
	"qq_auto":           utls.HelloQQ_Auto,
	"random":            utls.HelloRandomized,
	"randomized":        utls.HelloRandomized,
	"randomizedalpn":    utls.HelloRandomizedALPN,
	"randomizednoalpn":  utls.HelloRandomizedNoALPN,
	"safari":            utls.HelloSafari_Auto,
	"safari_16_0":       utls.HelloSafari_16_0,
	"safari_auto":       utls.HelloSafari_Auto,
}

// normalizeClientHelloRecord removes known upstream uTLS template defects
// from a captured ClientHello so the fixture can be regenerated deterministically:
//
//   - adjacent duplicate cipher suites (uTLS v1.3.3 HelloEdge_106 repeats
//     TLS_AES_256_GCM_SHA384 / 0x1302);
//   - adjacent duplicate signature schemes (uTLS v1.3.3 Safari/iOS templates
//     repeat SIG_RSA_PSS_RSAE_SHA384 / 0x0805).
//
// Real browsers never repeat a cipher suite or signature scheme, so these
// duplicates are template bugs, not wire behaviour. Removing bytes from the
// handshake would shift the RFC 7685 padding extension's target, so the
// padding extension (0x0015) is grown by the same number of bytes to keep
// the record length (and the fixture's padding target) identical otherwise.
//
// The function fails on any structure it does not understand, so a future
// uTLS upgrade that fixes the templates upstream produces an unchanged
// fixture instead of silently mutating it.
func normalizeClientHelloRecord(record []byte) ([]byte, error) {
	if len(record) < 5 || record[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record")
	}
	recLen := int(record[3])<<8 | int(record[4])
	if 5+recLen != len(record) {
		return nil, fmt.Errorf("record length mismatch")
	}
	if len(record) < 9 || record[5] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello handshake")
	}
	hsLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if 9+hsLen != len(record) {
		return nil, fmt.Errorf("handshake length mismatch")
	}

	off := 9 + 2 + 32 // handshake header + legacy_version + random
	if off >= len(record) {
		return nil, fmt.Errorf("truncated before session id")
	}
	sidLen := int(record[off])
	off += 1 + sidLen
	if off+2 > len(record) {
		return nil, fmt.Errorf("truncated before cipher suites")
	}
	cipherLen := int(record[off])<<8 | int(record[off+1])
	if cipherLen%2 != 0 {
		return nil, fmt.Errorf("cipher suites length is not even")
	}
	clenFieldStart := off
	cipherStart := off + 2
	cipherEnd := cipherStart + cipherLen
	if cipherEnd >= len(record) {
		// `record[cipherEnd]` (compression method length) is read right
		// after this check, so the cipher block must leave at least one
		// byte; a bare `>` would let cipherEnd == len(record) through and
		// panic on the index.
		return nil, fmt.Errorf("cipher suites out of bounds")
	}
	compLen := int(record[cipherEnd])
	extStart := cipherEnd + 1 + compLen
	if extStart+2 > len(record) {
		return nil, fmt.Errorf("truncated before extensions")
	}
	extTotal := int(record[extStart])<<8 | int(record[extStart+1])
	extEnd := extStart + 2 + extTotal
	if extEnd != len(record) {
		return nil, fmt.Errorf("extensions do not reach the record end")
	}

	// Deduplicate adjacent cipher suites (uTLS v1.3.3 HelloEdge_106 repeats
	// TLS_AES_256_GCM_SHA384 / 0x1302; real browsers never repeat).
	deduped := make([]uint16, 0, cipherLen/2)
	for i := cipherStart; i+2 <= cipherEnd; i += 2 {
		c := uint16(record[i])<<8 | uint16(record[i+1])
		if len(deduped) > 0 && deduped[len(deduped)-1] == c && c == 0x1302 {
			continue
		}
		deduped = append(deduped, c)
	}
	removedBytes := cipherLen - len(deduped)*2

	// Walk the extension block, deduplicating signature schemes (uTLS v1.3.3
	// Safari/iOS repeat SIG_RSA_PSS_RSAE_SHA384 / 0x0805) and growing the
	// padding extension by the removed bytes to keep the record length (and
	// the fixture's padding target) unchanged.
	type extension struct {
		etype uint16
		data  []byte
	}
	exts := make([]extension, 0, 16)
	paddingIndex := -1
	for p := extStart + 2; p < extEnd; {
		if p+4 > extEnd {
			return nil, fmt.Errorf("truncated extension header")
		}
		etype := uint16(record[p])<<8 | uint16(record[p+1])
		elen := int(record[p+2])<<8 | int(record[p+3])
		if p+4+elen > extEnd {
			return nil, fmt.Errorf("extension %#x out of bounds", etype)
		}
		data := append([]byte(nil), record[p+4:p+4+elen]...)
		switch etype {
		case 0x000d:
			// signature_algorithms
			if len(data) < 2 {
				return nil, fmt.Errorf("signature_algorithms extension is truncated")
			}
			listLen := int(data[0])<<8 | int(data[1])
			if listLen%2 != 0 || 2+listLen != len(data) {
				return nil, fmt.Errorf("signature_algorithms length mismatch")
			}
			algs := make([]uint16, 0, listLen/2)
			for i := 2; i < len(data); i += 2 {
				a := uint16(data[i])<<8 | uint16(data[i+1])
				if len(algs) > 0 && algs[len(algs)-1] == a && a == 0x0805 {
					continue
				}
				algs = append(algs, a)
			}
			if len(algs)*2 != listLen {
				rebuilt := make([]byte, 2+len(algs)*2)
				rebuilt[0] = byte(len(algs) * 2 >> 8)
				rebuilt[1] = byte(len(algs) * 2)
				for i, a := range algs {
					rebuilt[2+i*2] = byte(a >> 8)
					rebuilt[2+i*2+1] = byte(a)
				}
				removedBytes += listLen - len(algs)*2
				data = rebuilt
			}
		case 0x0015:
			if paddingIndex >= 0 {
				return nil, fmt.Errorf("duplicate padding extension")
			}
			paddingIndex = len(exts)
		}
		exts = append(exts, extension{etype: etype, data: data})
		p += 4 + elen
	}

	if removedBytes == 0 {
		return record, nil
	}
	if paddingIndex < 0 {
		return nil, fmt.Errorf("cannot preserve record length without a padding extension")
	}
	exts[paddingIndex].data = append(exts[paddingIndex].data, make([]byte, removedBytes)...)

	// Rebuild: prefix (excluding the original cipher length field) + new
	// cipher block + untouched compression block + new extension block.
	out := make([]byte, 0, len(record))
	out = append(out, record[:clenFieldStart]...)
	out = append(out, byte(len(deduped)*2>>8), byte(len(deduped)*2))
	for _, c := range deduped {
		out = append(out, byte(c>>8), byte(c))
	}
	out = append(out, record[cipherEnd:extStart]...) // comp_len + comp
	newExtTotal := 0
	for _, e := range exts {
		newExtTotal += 4 + len(e.data)
	}
	out = append(out, byte(newExtTotal>>8), byte(newExtTotal))
	for _, e := range exts {
		out = append(out, byte(e.etype>>8), byte(e.etype))
		out = append(out, byte(len(e.data)>>8), byte(len(e.data)))
		out = append(out, e.data...)
	}
	if len(out) != len(record) {
		return nil, fmt.Errorf("normalization changed record length %d -> %d", len(record), len(out))
	}
	return out, nil
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
