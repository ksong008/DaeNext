/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func httpFileSubscriptionURL(tag string, rawURL string) string {
	return tag + ":" + strings.Replace(rawURL, "http://", "http-file://", 1)
}

func TestHTTPFileSubscriptionPersistsSafeTag(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("ss://example"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	configDir := t.TempDir()
	tag, nodes, err := ResolveSubscription(logrus.New(), server.Client(), configDir, httpFileSubscriptionURL("safe-tag", server.URL))
	if err != nil {
		t.Fatalf("ResolveSubscription() returned error: %v", err)
	}
	if tag != "safe-tag" {
		t.Fatalf("tag = %q, want safe-tag", tag)
	}
	if len(nodes) != 1 || nodes[0] != "ss://example" {
		t.Fatalf("nodes = %#v, want ss://example", nodes)
	}

	persisted, err := os.ReadFile(filepath.Join(configDir, "persist.d", "safe-tag.sub"))
	if err != nil {
		t.Fatalf("read persisted subscription: %v", err)
	}
	if strings.TrimSpace(string(persisted)) != payload {
		t.Fatalf("persisted payload = %q, want %q", strings.TrimSpace(string(persisted)), payload)
	}
}

func TestHTTPFileSubscriptionRejectsTagPathTraversal(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("ss://example"))))
	}))
	defer server.Close()

	configDir := t.TempDir()
	_, _, err := ResolveSubscription(logrus.New(), server.Client(), configDir, httpFileSubscriptionURL("../../escape", server.URL))
	if err == nil {
		t.Fatal("expected ResolveSubscription() to reject traversal tag")
	}
	if !strings.Contains(err.Error(), "persist filename") {
		t.Fatalf("error = %v, want persist filename", err)
	}
	if called {
		t.Fatal("server was called before rejecting unsafe tag")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(configDir), "escape.sub")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaped file stat error = %v, want not exist", err)
	}
}
