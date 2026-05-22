package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
)

type fixture struct {
	Name       string   `json:"name"`
	Stage      string   `json:"stage"`
	Source     []string `json:"source"`
	ServerName string   `json:"server_name"`
	ALPN       []string `json:"alpn"`
	Samples    []sample `json:"samples"`
}

type sample struct {
	Fingerprint string  `json:"fingerprint"`
	RecordHex   string  `json:"record_hex"`
	Profile     profile `json:"profile"`
}

type profile struct {
	RecordContentType  string   `json:"record_content_type"`
	RecordVersion      string   `json:"record_version"`
	RecordLen          int      `json:"record_len"`
	HandshakeType      string   `json:"handshake_type"`
	HandshakeLen       int      `json:"handshake_len"`
	LegacyVersion      string   `json:"legacy_version"`
	RandomLen          int      `json:"random_len"`
	SessionIDLen       int      `json:"session_id_len"`
	CipherSuites       []string `json:"cipher_suites"`
	CompressionMethods []string `json:"compression_methods"`
	ExtensionTypes     []string `json:"extension_types"`
	SNI                string   `json:"sni"`
	ALPN               []string `json:"alpn"`
	SupportedVersions  []string `json:"supported_versions"`
	SupportedGroups    []string `json:"supported_groups"`
	ECPointFormats     []string `json:"ec_point_formats"`
	SignatureSchemes   []string `json:"signature_schemes"`
	KeyShareGroups     []string `json:"key_share_groups"`
}

func main() {
	serverName := "stage139-utls.example"
	alpn := []string{"h2", "http/1.1"}
	names := []string{
		"chrome_102",
		"firefox_105",
		"safari_16_0",
		"ios_14",
		"edge_106",
		"android_11_okhttp",
	}
	out := fixture{
		Name:       "stage139-go-utls-clienthello-profile-fixture",
		Stage:      "stage139",
		ServerName: serverName,
		ALPN:       alpn,
		Source: []string{
			"/root/project/outbound/transport/tls/utls.go",
			"/root/project/outbound/transport/tls/tls.go",
			"github.com/refraction-networking/utls",
		},
	}
	for _, name := range names {
		id, err := clientHelloID(name)
		if err != nil {
			fatal(err)
		}
		record, err := captureClientHello(*id, serverName, alpn)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", name, err))
		}
		prof, err := parseClientHello(record)
		if err != nil {
			fatal(fmt.Errorf("%s parse: %w", name, err))
		}
		out.Samples = append(out.Samples, sample{
			Fingerprint: name,
			RecordHex:   hex.EncodeToString(record),
			Profile:     prof,
		})
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err)
	}
}

func captureClientHello(id utls.ClientHelloID, serverName string, alpn []string) ([]byte, error) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	errCh := make(chan error, 1)
	go func() {
		uconn := utls.UClient(client, &utls.Config{
			ServerName:         serverName,
			NextProtos:         alpn,
			InsecureSkipVerify: true,
		}, id)
		errCh <- uconn.Handshake()
	}()
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		return nil, err
	}
	recordLen := int(header[3])<<8 | int(header[4])
	body := make([]byte, recordLen)
	if _, err := io.ReadFull(server, body); err != nil {
		return nil, err
	}
	_ = client.Close()
	_ = server.Close()
	<-errCh
	return append(header, body...), nil
}

func parseClientHello(record []byte) (profile, error) {
	var p profile
	if len(record) < 9 {
		return p, fmt.Errorf("record too short")
	}
	p.RecordContentType = hexByte(record[0])
	p.RecordVersion = hexU16(record[1:3])
	p.RecordLen = int(record[3])<<8 | int(record[4])
	if len(record) != 5+p.RecordLen {
		return p, fmt.Errorf("record length mismatch")
	}
	body := record[5:]
	p.HandshakeType = hexByte(body[0])
	p.HandshakeLen = int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if len(body) != 4+p.HandshakeLen {
		return p, fmt.Errorf("handshake length mismatch")
	}
	hello := body[4:]
	if len(hello) < 38 {
		return p, fmt.Errorf("hello too short")
	}
	p.LegacyVersion = hexU16(hello[0:2])
	p.RandomLen = 32
	offset := 34
	p.SessionIDLen = int(hello[offset])
	offset++
	offset += p.SessionIDLen
	if offset+2 > len(hello) {
		return p, fmt.Errorf("cipher suites length missing")
	}
	cipherLen := int(hello[offset])<<8 | int(hello[offset+1])
	offset += 2
	if offset+cipherLen > len(hello) || cipherLen%2 != 0 {
		return p, fmt.Errorf("bad cipher suites length")
	}
	p.CipherSuites = hexU16List(hello[offset : offset+cipherLen])
	offset += cipherLen
	if offset >= len(hello) {
		return p, fmt.Errorf("compression methods missing")
	}
	compressionLen := int(hello[offset])
	offset++
	if offset+compressionLen > len(hello) {
		return p, fmt.Errorf("bad compression methods length")
	}
	for _, value := range hello[offset : offset+compressionLen] {
		p.CompressionMethods = append(p.CompressionMethods, hexByte(value))
	}
	offset += compressionLen
	if offset == len(hello) {
		return p, nil
	}
	if offset+2 > len(hello) {
		return p, fmt.Errorf("extensions length missing")
	}
	extensionsLen := int(hello[offset])<<8 | int(hello[offset+1])
	offset += 2
	end := offset + extensionsLen
	if end > len(hello) {
		return p, fmt.Errorf("bad extensions length")
	}
	for offset < end {
		if offset+4 > end {
			return p, fmt.Errorf("extension header truncated")
		}
		typ := hello[offset : offset+2]
		extType := hexU16(typ)
		extLen := int(hello[offset+2])<<8 | int(hello[offset+3])
		offset += 4
		if offset+extLen > end {
			return p, fmt.Errorf("extension body truncated")
		}
		data := hello[offset : offset+extLen]
		p.ExtensionTypes = append(p.ExtensionTypes, extType)
		switch extType {
		case "0000":
			p.SNI = parseSNI(data)
		case "000a":
			p.SupportedGroups = parseU16Vector(data)
		case "000b":
			p.ECPointFormats = parseU8Vector(data)
		case "000d":
			p.SignatureSchemes = parseU16Vector(data)
		case "0010":
			p.ALPN = parseALPN(data)
		case "002b":
			p.SupportedVersions = parseU8LenU16Vector(data)
		case "0033":
			p.KeyShareGroups = parseKeyShareGroups(data)
		}
		offset += extLen
	}
	return p, nil
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(data[0])<<8 | int(data[1])
	if 2+listLen > len(data) || data[2] != 0 {
		return ""
	}
	nameLen := int(data[3])<<8 | int(data[4])
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(data[0])<<8 | int(data[1])
	offset := 2
	end := offset + listLen
	var out []string
	for offset < end && offset < len(data) {
		n := int(data[offset])
		offset++
		if offset+n > len(data) {
			return out
		}
		out = append(out, string(data[offset:offset+n]))
		offset += n
	}
	return out
}

func parseU16Vector(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	n := int(data[0])<<8 | int(data[1])
	if 2+n > len(data) {
		return nil
	}
	return hexU16List(data[2 : 2+n])
}

func parseU8LenU16Vector(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	if 1+n > len(data) {
		return nil
	}
	return hexU16List(data[1 : 1+n])
}

func parseU8Vector(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	n := int(data[0])
	if 1+n > len(data) {
		return nil
	}
	var out []string
	for _, value := range data[1 : 1+n] {
		out = append(out, hexByte(value))
	}
	return out
}

func parseKeyShareGroups(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	n := int(data[0])<<8 | int(data[1])
	offset := 2
	end := offset + n
	var out []string
	for offset+4 <= end && offset+4 <= len(data) {
		out = append(out, hexU16(data[offset:offset+2]))
		keyLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4 + keyLen
	}
	return out
}

func hexU16List(data []byte) []string {
	var out []string
	for i := 0; i+1 < len(data); i += 2 {
		out = append(out, hexU16(data[i:i+2]))
	}
	return out
}

func hexByte(value byte) string {
	return fmt.Sprintf("%02x", value)
}

func hexU16(value []byte) string {
	return fmt.Sprintf("%02x%02x", value[0], value[1])
}

func clientHelloID(name string) (*utls.ClientHelloID, error) {
	switch name {
	case "chrome_102":
		return &utls.HelloChrome_102, nil
	case "firefox_105":
		return &utls.HelloFirefox_105, nil
	case "safari_16_0":
		return &utls.HelloSafari_16_0, nil
	case "ios_14":
		return &utls.HelloIOS_14, nil
	case "edge_106":
		return &utls.HelloEdge_106, nil
	case "android_11_okhttp":
		return &utls.HelloAndroid_11_OkHttp, nil
	default:
		return nil, fmt.Errorf("unsupported fixture fingerprint: %s", name)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
