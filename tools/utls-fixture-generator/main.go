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

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
