/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	outbounddialer "github.com/daeuniverse/outbound/dialer"
	outboundssdialer "github.com/daeuniverse/outbound/dialer/shadowsocks"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	outboundprotocol "github.com/daeuniverse/outbound/protocol"
	outboundss "github.com/daeuniverse/outbound/protocol/shadowsocks"
	outboundss2022 "github.com/daeuniverse/outbound/protocol/shadowsocks_2022"
	outboundsocks5 "github.com/daeuniverse/outbound/protocol/socks5"
)

const (
	stage15SSPassword = "password"
	stage15SSPSK128   = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
	stage15SSPSK256   = "MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY="
)

func TestWriteShadowsocksNativeOptInGoldenFixture(t *testing.T) {
	writeOrCheckOutboundGolden(t,
		"../../testdata/rebuild-golden/outbound/protocol/shadowsocks_native_optin.json",
		rebuildGoldenStage15ShadowsocksNativeOptIn(t),
	)
}

func rebuildGoldenStage15ShadowsocksNativeOptIn(t testing.TB) any {
	t.Helper()

	return map[string]any{
		"name": "stage15-shadowsocks-native-optin",
		"source": []string{
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:12.5",
			"DAENEW_RUST_REBUILD_MEMO_2026-05-16.md:26.9",
			"/root/project/outbound/dialer/shadowsocks/shadowsocks.go",
			"/root/project/outbound/dialer/shadowsocks/shadowsocks_ss2022_test.go",
			"/root/project/outbound/protocol/shadowsocks/addr.go",
			"/root/project/outbound/protocol/shadowsocks_2022/dialer.go",
			"/root/project/outbound/protocol/shadowsocks_2022/tcp_conn.go",
			"/root/project/outbound/protocol/shadowsocks_2022/udp_conn.go",
			"/root/project/outbound/protocol/shadowsocks_2022/replay_filter.go",
		},
		"default_go_path":   true,
		"rust_adapter_mode": "native-opt-in",
		"protocol_scope": []string{
			"shadowsocks",
			"shadowsocks-2022",
		},
		"deferred_protocol_scope": []string{
			"shadowsocksr",
			"trojan",
			"vmess",
			"vless",
			"hysteria2",
			"tuic",
			"juicity",
			"anytls",
			"transport-combos",
		},
		"link_parser": []map[string]any{
			rebuildShadowsocksLinkCase(t, "sip002-aead-base64-userinfo", stage15SSAeadLink("node")),
			rebuildShadowsocksLinkCase(t, "ss2022-plain-userinfo", stage15SS2022Link("ss2022", stage15SSPSK128)),
			rebuildShadowsocksLinkCase(t, "ss2022-multi-psk", stage15SS2022Link("multi", stage15SSPSK128+":"+stage15SSPSK128)),
			rebuildShadowsocksLinkCase(t, "simple-obfs-plugin", stage15SSPluginLink("simple")),
			rebuildShadowsocksLinkCase(t, "v2ray-plugin-tls", stage15SSV2RayPluginLink("v2ray")),
		},
		"cipher_dispatch": []map[string]any{
			rebuildShadowsocksCipherCase(t, "aead", "aes-128-gcm", stage15SSPassword),
			rebuildShadowsocksCipherCase(t, "ss2022-aes128", "2022-blake3-aes-128-gcm", stage15SSPSK128),
			rebuildShadowsocksCipherCase(t, "ss2022-chacha20", "2022-blake3-chacha20-poly1305", stage15SSPSK256),
			rebuildShadowsocksCipherCase(t, "stream-legacy", "aes-128-cfb", stage15SSPassword),
		},
		"metadata": []map[string]any{
			rebuildShadowsocksMetadataCase(t, "domain", "example.com:443"),
			rebuildShadowsocksMetadataCase(t, "ipv4", "1.2.3.4:53"),
			rebuildShadowsocksMetadataCase(t, "ipv6", "[2001:db8::1]:8443"),
		},
		"ss2022": map[string]any{
			"cipher_conf": []map[string]any{
				rebuildShadowsocks2022CipherConf("2022-blake3-aes-128-gcm"),
				rebuildShadowsocks2022CipherConf("2022-blake3-aes-256-gcm"),
				rebuildShadowsocks2022CipherConf("2022-blake3-chacha20-poly1305"),
			},
			"psk": []map[string]any{
				rebuildShadowsocks2022PSKCase(t, "single-aes128", "2022-blake3-aes-128-gcm", stage15SSPSK128),
				rebuildShadowsocks2022PSKCase(t, "multi-aes128", "2022-blake3-aes-128-gcm", stage15SSPSK128+":"+stage15SSPSK128),
				rebuildShadowsocks2022PSKCase(t, "single-chacha20", "2022-blake3-chacha20-poly1305", stage15SSPSK256),
			},
			"tcp_header":    rebuildShadowsocks2022TCPHeaderContract(t),
			"udp_packet_id": rebuildShadowsocks2022UDPPacketIDContract(t),
			"replay_filter": rebuildShadowsocks2022ReplayContract(),
		},
		"sip003": map[string]any{
			"simple_obfs_aliases": []string{
				"obfs-local",
				"simpleobfs",
			},
			"path_without_slash_go_behavior": "append-trailing-slash",
			"default_simple_obfs_host":       "cloudflare.com",
			"v2ray_plugin_udp_passthrough_layers": []string{
				"tls when tls option is present",
				"ws",
				"mux",
			},
			"transport_native_data_plane_deferred_to_item": 113,
		},
		"live_smoke_required": []string{
			"local parser smoke for SIP002 AEAD",
			"local parser smoke for SS2022 single and multi PSK",
			"local metadata/framing smoke",
			"local replay filter smoke",
		},
	}
}

func rebuildShadowsocksLinkCase(t testing.TB, name string, raw string) map[string]any {
	t.Helper()

	ss, err := outboundssdialer.ParseSSURL(raw)
	if err != nil {
		t.Fatalf("ParseSSURL(%q): %v", raw, err)
	}
	_, property, err := outbounddialer.NewNetproxyDialerFromLink(
		noDialSocks5Dialer{},
		&outbounddialer.ExtraOption{},
		raw,
	)
	if err != nil {
		t.Fatalf("NewNetproxyDialerFromLink(%q): %v", raw, err)
	}
	return map[string]any{
		"name":              name,
		"input":             raw,
		"server":            ss.Server,
		"port":              ss.Port,
		"cipher":            ss.Cipher,
		"password":          ss.Password,
		"udp":               ss.UDP,
		"protocol":          ss.Protocol,
		"export":            ss.ExportToURL(),
		"property_name":     property.Name,
		"property_address":  property.Address,
		"property_protocol": property.Protocol,
		"property_link":     property.Link,
		"plugin": map[string]any{
			"name": ss.Plugin.Name,
			"tls":  ss.Plugin.Opts.Tls,
			"obfs": ss.Plugin.Opts.Obfs,
			"host": ss.Plugin.Opts.Host,
			"path": ss.Plugin.Opts.Path,
		},
	}
}

func rebuildShadowsocksCipherCase(t testing.TB, name string, cipher string, password string) map[string]any {
	t.Helper()

	ss := &outboundssdialer.Shadowsocks{
		Name:     name,
		Server:   "example.com",
		Port:     8388,
		Password: password,
		Cipher:   cipher,
		Protocol: "shadowsocks",
	}
	dialer, _, err := ss.Dialer(&outbounddialer.ExtraOption{}, noDialSocks5Dialer{})
	if err != nil {
		t.Fatalf("Dialer(%q): %v", cipher, err)
	}
	dialerType := reflect.TypeOf(dialer).String()
	return map[string]any{
		"name":                    name,
		"cipher":                  cipher,
		"go_protocol_dialer":      goProtocolFromDialerType(dialerType),
		"concrete_dialer_type":    dialerType,
		"rust_capability_label":   rustShadowsocksCapabilityLabel(cipher),
		"export_userinfo_plain":   strings.HasPrefix(strings.ToLower(cipher), "2022-blake3-"),
		"property_protocol_stays": "shadowsocks",
	}
}

func rebuildShadowsocksMetadataCase(t testing.TB, name string, target string) map[string]any {
	t.Helper()

	meta, err := outboundprotocol.ParseMetadata(target)
	if err != nil {
		t.Fatalf("ParseMetadata(%q): %v", target, err)
	}
	ssMeta := outboundss.Metadata{Metadata: meta}
	encoded, err := ssMeta.Bytes()
	if err != nil {
		t.Fatalf("Metadata.Bytes(%q): %v", target, err)
	}
	decoded, err := outboundss.NewMetadata(encoded)
	if err != nil {
		t.Fatalf("NewMetadata(%q): %v", target, err)
	}
	return map[string]any{
		"name":     name,
		"input":    target,
		"type":     outboundss.MetadataTypeToByte(meta.Type),
		"hostname": decoded.Hostname,
		"port":     decoded.Port,
		"hex":      hex.EncodeToString(encoded),
	}
}

func rebuildShadowsocks2022CipherConf(cipher string) map[string]any {
	conf := ciphers.Aead2022CiphersConf[cipher]
	return map[string]any{
		"cipher":           cipher,
		"key_len":          conf.KeyLen,
		"salt_len":         conf.SaltLen,
		"nonce_len":        conf.NonceLen,
		"tag_len":          conf.TagLen,
		"packet_nonce_len": conf.PacketNonceLen,
		"packet_cipher":    conf.NewPacketCipher != nil,
	}
}

func rebuildShadowsocks2022PSKCase(t testing.TB, name string, cipher string, password string) map[string]any {
	t.Helper()

	conf := ciphers.Aead2022CiphersConf[cipher]
	parts := strings.Split(password, ":")
	keyLens := make([]int, 0, len(parts))
	for _, part := range parts {
		key, err := ciphers.ValidateBase64PSK(part, conf.KeyLen)
		if err != nil {
			t.Fatalf("ValidateBase64PSK(%q): %v", name, err)
		}
		keyLens = append(keyLens, len(key))
	}
	return map[string]any{
		"name":             name,
		"cipher":           cipher,
		"password":         password,
		"psk_count":        len(parts),
		"psk_key_lens":     keyLens,
		"upsk_index":       len(parts) - 1,
		"expected_key_len": conf.KeyLen,
	}
}

func rebuildShadowsocks2022TCPHeaderContract(t testing.TB) map[string]any {
	t.Helper()

	payload := []byte{}
	addr, err := outboundsocks5.AddressFromString("example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	fixedHeader, varHeader, err := outboundss2022.EncodeRequestHeader(outboundss2022.HeaderTypeClientStream, 1, addr, &payload)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.PutBuffer(fixedHeader)
	defer pool.PutBuffer(varHeader)

	addrBuf := &bytes.Buffer{}
	if err := outboundsocks5.WriteAddrInfo(addr, addrBuf); err != nil {
		t.Fatal(err)
	}
	paddingOffset := addrBuf.Len()
	paddingLen := binary.BigEndian.Uint16(varHeader.Bytes()[paddingOffset : paddingOffset+2])
	return map[string]any{
		"fixed_header_len":                  fixedHeader.Len(),
		"header_type_client_stream":         outboundss2022.HeaderTypeClientStream,
		"timestamp":                         1,
		"target":                            "example.com:443",
		"address_hex":                       hex.EncodeToString(addrBuf.Bytes()),
		"var_header_len_min":                addrBuf.Len() + 2,
		"empty_initial_payload_has_padding": paddingLen > 0,
		"max_padding_len":                   outboundss2022.MaxPaddingLength,
	}
}

func rebuildShadowsocks2022UDPPacketIDContract(t testing.TB) map[string]any {
	t.Helper()

	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	uPSK, err := ciphers.ValidateBase64PSK(stage15SSPSK128, conf.KeyLen)
	if err != nil {
		t.Fatal(err)
	}
	block, err := conf.NewBlockCipher(uPSK)
	if err != nil {
		t.Fatal(err)
	}
	conn := &stage15PacketBufferConn{}
	udpConn, err := outboundss2022.NewUdpConn(conn, "1.1.1.1:53", conf, block, block, [][]byte{uPSK}, uPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpConn.WriteTo([]byte("hello"), "1.1.1.1:53"); err != nil {
		t.Fatal(err)
	}

	header := make([]byte, 16)
	block.Decrypt(header, conn.write.Bytes()[:16])
	return map[string]any{
		"cipher":                   "2022-blake3-aes-128-gcm",
		"first_packet_id":          binary.BigEndian.Uint64(header[8:16]),
		"separate_header_len":      16,
		"packet_id_big_endian":     true,
		"replay_window_size":       outboundss2022.UDPReplayWindowSize,
		"server_session_retention": outboundss2022.ServerSessionRetention.String(),
	}
}

func rebuildShadowsocks2022ReplayContract() map[string]any {
	duplicate := outboundss2022.NewSlidingWindowFilter(4)
	first := duplicate.CheckAndUpdate(1)
	second := duplicate.CheckAndUpdate(1)

	old := outboundss2022.NewSlidingWindowFilter(4)
	accepted := []bool{}
	for _, packetID := range []uint64{10, 11, 12, 13, 14} {
		accepted = append(accepted, old.CheckAndUpdate(packetID))
	}
	tooOld := old.CheckAndUpdate(10)

	return map[string]any{
		"window":                    4,
		"first_packet_accepted":     first,
		"duplicate_packet_accepted": second,
		"monotonic_accepts":         accepted,
		"too_old_packet_accepted":   tooOld,
	}
}

type stage15PacketBufferConn struct {
	read  *bytes.Reader
	write bytes.Buffer
}

func (c *stage15PacketBufferConn) Read(p []byte) (int, error) {
	if c.read == nil {
		return 0, net.ErrClosed
	}
	return c.read.Read(p)
}

func (c *stage15PacketBufferConn) Write(p []byte) (int, error) {
	return c.write.Write(p)
}

func (c *stage15PacketBufferConn) Close() error                     { return nil }
func (c *stage15PacketBufferConn) SetDeadline(time.Time) error      { return nil }
func (c *stage15PacketBufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stage15PacketBufferConn) SetWriteDeadline(time.Time) error { return nil }

var _ netproxy.Conn = (*stage15PacketBufferConn)(nil)

func stage15SSAeadLink(name string) string {
	user := strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:"+stage15SSPassword)), "=")
	return "ss://" + user + "@example.com:8388#" + name
}

func stage15SS2022Link(name string, password string) string {
	u := &url.URL{
		Scheme:   "ss",
		Host:     "example.com:443",
		Fragment: name,
	}
	u.User = url.UserPassword("2022-blake3-aes-128-gcm", password)
	return u.String()
}

func stage15SSPluginLink(name string) string {
	u := &url.URL{
		Scheme:   "ss",
		Host:     "example.com:8388",
		Fragment: name,
	}
	u.User = url.User(strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:"+stage15SSPassword)), "="))
	q := u.Query()
	q.Set("plugin", "simpleobfs;obfs=http;obfs-host=front.example;obfs-uri=abc")
	u.RawQuery = q.Encode()
	return u.String()
}

func stage15SSV2RayPluginLink(name string) string {
	u := &url.URL{
		Scheme:   "ss",
		Host:     "example.com:8388",
		Fragment: name,
	}
	u.User = url.User(strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte("aes-128-gcm:"+stage15SSPassword)), "="))
	q := u.Query()
	q.Set("plugin", "v2ray-plugin;tls;host=front.example")
	u.RawQuery = q.Encode()
	return u.String()
}

func goProtocolFromDialerType(dialerType string) string {
	switch {
	case strings.Contains(dialerType, "shadowsocks_2022"):
		return "shadowsocks_2022"
	case strings.Contains(dialerType, "shadowsocks_stream"):
		return "shadowsocks_stream"
	default:
		return "shadowsocks"
	}
}

func rustShadowsocksCapabilityLabel(cipher string) string {
	if strings.HasPrefix(strings.ToLower(cipher), "2022-blake3-") {
		return "shadowsocks-2022"
	}
	return "shadowsocks"
}

var shadowsocksNativeOptInBenchmarkSink int

func BenchmarkShadowsocksNativeOptInParseLink(b *testing.B) {
	link := stage15SS2022Link("bench", stage15SSPSK128+":"+stage15SSPSK128)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		parsed, err := outboundssdialer.ParseSSURL(link)
		if err != nil {
			b.Fatal(err)
		}
		shadowsocksNativeOptInBenchmarkSink ^= len(parsed.Server) ^ parsed.Port ^ len(parsed.Password)
	}
}

func BenchmarkShadowsocksNativeOptInMetadataBytes(b *testing.B) {
	meta, err := outboundprotocol.ParseMetadata("example.com:443")
	if err != nil {
		b.Fatal(err)
	}
	ssMeta := outboundss.Metadata{Metadata: meta}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ssMeta.Bytes(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShadowsocksNativeOptInSS2022PSKSplit(b *testing.B) {
	password := stage15SSPSK128 + ":" + stage15SSPSK128
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"]
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, keyStr := range strings.Split(password, ":") {
			if _, err := ciphers.ValidateBase64PSK(keyStr, conf.KeyLen); err != nil {
				b.Fatal(err)
			}
		}
	}
}
