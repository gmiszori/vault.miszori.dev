package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrustedProxyCIDRConfig(t *testing.T) {
	for _, tc := range []struct{ value, want string }{
		{"", "172.30.0.0/24"},
		{"172.29.0.0/24", "172.29.0.0/24"},
		{"10.1.2.3/32", "10.1.2.3/32"},
		{"192.168.2.0/24", "192.168.2.0/24"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Setenv("PUBLIC_LISTEN_ADDR", "127.0.0.1:8080")
			t.Setenv("ADMIN_LISTEN_ADDR", "127.0.0.1:8081")
			t.Setenv("ADMIN_PROXY_IP", "127.0.0.1")
			t.Setenv("TRUSTED_PROXY_CIDR", tc.value)
			config, err := listenerConfigFromEnv()
			if err != nil || config.trustedProxy.String() != tc.want {
				t.Fatalf("proxy CIDR = %v, want %s: %v", config.trustedProxy, tc.want, err)
			}
			if !config.adminProxy.Equal(net.ParseIP("127.0.0.1")) {
				t.Fatal("forwarding CIDR changed the independent admin socket guard")
			}
		})
	}
	for prefix := 24; prefix <= 32; prefix++ {
		if _, err := parseTrustedProxyCIDR(fmt.Sprintf("172.29.0.0/%d", prefix)); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"172.29.0.1", "172.29.0.0/33", " 172.29.0.0/24", "172.29.0.0/24,172.30.0.0/24", "192.0.2.0/24", "::/0"} {
		if _, err := parseTrustedProxyCIDR(value); err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDR") {
			t.Fatalf("invalid CIDR %q was not clearly rejected: %v", value, err)
		}
	}
}

func TestTrustedProxyForwarding(t *testing.T) {
	for _, tc := range []struct {
		name, cidr string
		peers      map[string]string
	}{
		{"constructor default", "", map[string]string{
			"172.30.0.0:1234":   "203.0.113.7",
			"172.30.0.255:1234": "203.0.113.7",
			"172.29.0.3:1234":   "172.29.0.3",
			"172.30.1.0:1234":   "172.30.1.0",
			"192.0.2.1:1234":    "192.0.2.1",
			"[::1]:1234":        "::1",
			"invalid":           "",
		}},
		{"custom subnet", "172.29.0.0/24", map[string]string{
			"172.29.0.0:1234":     "203.0.113.7",
			"172.29.0.255:1234":   "203.0.113.7",
			"172.30.0.3:1234":     "172.30.0.3",
			"172.28.255.255:1234": "172.28.255.255",
			"172.29.1.0:1234":     "172.29.1.0",
		}},
		{"single proxy", "10.1.2.3/32", map[string]string{
			"10.1.2.3:1234": "203.0.113.7",
			"10.1.2.2:1234": "10.1.2.2",
			"10.1.2.4:1234": "10.1.2.4",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			if tc.cidr != "" {
				var err error
				s.trustedProxy, err = parseTrustedProxyCIDR(tc.cidr)
				if err != nil {
					t.Fatal(err)
				}
			}
			for peer, want := range tc.peers {
				r := httptest.NewRequest("GET", "/", nil)
				r.RemoteAddr = peer
				r.Header.Set("X-Real-IP", "203.0.113.7")
				if got := s.peerIP(r); got != want {
					t.Fatalf("peer %s forwarded as %s, want %s", peer, got, want)
				}
			}
		})
	}
	s := testServer(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.30.0.3:1234"
	r.Header.Set("X-Real-IP", "invalid")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("Forwarded", "for=203.0.113.7")
	if got := s.peerIP(r); got != "172.30.0.3" {
		t.Fatal("invalid X-Real-IP trusted other forwarding headers", got)
	}
	s.trustedProxy = nil
	r.Header.Set("X-Real-IP", "203.0.113.7")
	if got := s.peerIP(r); got != "172.30.0.3" {
		t.Fatal("missing proxy configuration broadened trust", got)
	}
}

func TestCustomProxyAttributionAndIndependentAdminGuard(t *testing.T) {
	s := testServer(t)
	var err error
	s.trustedProxy, err = parseTrustedProxyCIDR("172.29.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	id := reusablePackage(t, s)
	for _, tc := range []struct{ method, path, key string }{
		{"GET", "/api/packages/invalid", "public:203.0.113.7"},
		{"GET", "/api/admin/auth", "discovery:203.0.113.7"},
		{"GET", "/api/admin/config", "auth:203.0.113.7"},
		{"POST", "/api/packages/" + id + "/consume", "public:203.0.113.7"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.RemoteAddr = "172.29.0.3:1234"
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if s.limits[tc.key].count == 0 {
			t.Fatalf("%s did not attribute rate limits to configured forwarding peer", tc.path)
		}
	}
	if page := auditPage(t, s, id, ""); len(page.Retrievals) != 1 || page.Retrievals[0].OpenedIP != "203.0.113.7" {
		t.Fatal("retrieval audit ignored configured forwarding peer", page)
	}
	for _, tc := range []struct {
		peer string
		want int
	}{
		{"172.29.0.3:1234", 404},
		{"172.30.0.131:1234", 200},
	} {
		r := httptest.NewRequest("GET", "/api/admin/config", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Real-IP", "172.30.0.131")
		r.SetBasicAuth("admin", testAuthentication)
		w := httptest.NewRecorder()
		s.adminHandler(net.ParseIP("172.30.0.131")).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("forwarding CIDR changed admin socket guard: peer %s returned %d", tc.peer, w.Code)
		}
	}
}

func TestMainProxyConfigProcess(t *testing.T) {
	mode := os.Getenv("VAULT_TEST_MAIN_MODE")
	if mode == "" {
		return
	}
	os.Args = []string{"vault"}
	if mode == "healthcheck" {
		os.Args = append(os.Args, mode)
	}
	main()
}

func TestMainAndHealthcheckValidateProxyEnv(t *testing.T) {
	ready := func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"ok":true}`) }
	public := httptest.NewServer(http.HandlerFunc(ready))
	defer public.Close()
	admin := httptest.NewServer(http.HandlerFunc(ready))
	defer admin.Close()
	blockedStorage := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedStorage, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"main", "healthcheck"} {
		for _, cidr := range []string{"", "172.29.0.0/24", "0.0.0.0/0"} {
			t.Run(mode+"/"+cidr, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainProxyConfigProcess$")
				cmd.Env = append(os.Environ(),
					"VAULT_TEST_MAIN_MODE="+mode,
					"TRUSTED_PROXY_CIDR="+cidr,
					"PUBLIC_LISTEN_ADDR="+public.Listener.Addr().String(),
					"ADMIN_LISTEN_ADDR="+admin.Listener.Addr().String(),
					"ADMIN_PROXY_IP=127.0.0.1",
					"DATA_DIR="+blockedStorage,
				)
				output, err := cmd.CombinedOutput()
				if ctx.Err() != nil {
					t.Fatalf("configuration validation hung: %s", output)
				}
				if cidr == "0.0.0.0/0" {
					if err == nil || !strings.Contains(string(output), "TRUSTED_PROXY_CIDR must be a private IPv4 CIDR") {
						t.Fatalf("%s did not reject unsafe proxy configuration before other work: %v %s", mode, err, output)
					}
				} else if mode == "healthcheck" {
					if err != nil {
						t.Fatalf("valid proxy CIDR rejected by healthcheck: %v %s", err, output)
					}
				} else if err == nil || !strings.Contains(string(output), "Cannot initialize storage") {
					t.Fatalf("valid proxy CIDR did not reach normal main startup: %v %s", err, output)
				}
			})
		}
	}
}
