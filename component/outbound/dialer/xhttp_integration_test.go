//go:build linux

package dialer_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"path"
	"strconv"
	"sync"
	"testing"
	"time"

	_ "github.com/daeuniverse/dae/component/outbound"
	daedialer "github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	outbounddirect "github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	"github.com/sirupsen/logrus"
)

type h3Session struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}

func TestNewFromLinkXHTTPH3Auto(t *testing.T) {
	cert := generateSelfSignedCert(t)

	var (
		mu       sync.Mutex
		sessions = make(map[string]*h3Session)
	)
	getSession := func(key string) *h3Session {
		key = path.Base(key)
		mu.Lock()
		defer mu.Unlock()
		if sess, ok := sessions[key]; ok {
			return sess
		}
		pr, pw := io.Pipe()
		sess := &h3Session{reader: pr, writer: pw}
		sessions[key] = sess
		return sess
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r.URL.Path)
		switch r.Method {
		case http.MethodGet:
			flusher, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			if flusher != nil {
				flusher.Flush()
			}
			buf := make([]byte, 32*1024)
			for {
				n, err := sess.reader.Read(buf)
				if n > 0 {
					if _, writeErr := w.Write(buf[:n]); writeErr != nil {
						return
					}
					if flusher != nil {
						flusher.Flush()
					}
				}
				if err != nil {
					return
				}
			}
		case http.MethodPost:
			defer sess.writer.Close()
			if _, err := io.Copy(sess.writer, r.Body); err != nil {
				t.Logf("server copy error: %v", err)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := &http3.Server{
		Handler:   handler,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	ln, err := quic.ListenAddrEarly("127.0.0.1:0", server.TLSConfig, &quic.Config{})
	if err != nil {
		t.Fatalf("listen h3: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ServeListener(ln)
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serverErr:
		case <-time.After(time.Second):
		}
	}()

	outbounddirect.InitDirectDialers("8.8.8.8:53")
	gOption := daedialer.NewGlobalOption(&config.Global{}, logrus.New())
	link := "vless://uuid@127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.UDPAddr).Port) + "?type=xhttp&security=tls&host=127.0.0.1&sni=127.0.0.1&allowInsecure=true&alpn=h3&mode=auto#xhttp-h3"

	d, err := daedialer.NewFromLink(gOption, daedialer.InstanceOption{}, link, "")
	if err != nil {
		t.Fatalf("new from link: %v", err)
	}
	defer d.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(netip.MustParseAddr("1.1.1.1").String(), "443"))
	if err != nil {
		t.Fatalf("dial context: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello through dae xhttp h3")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if xc, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := xc.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("unexpected echo: got %q want %q", string(buf), string(payload))
	}
}
