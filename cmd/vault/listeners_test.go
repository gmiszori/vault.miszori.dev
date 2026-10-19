package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListenerBoundaries(t *testing.T) {
	s := testServer(t)
	proxy := net.ParseIP("172.30.0.131")
	for _, tc := range []struct {
		name, path, peer string
		handler          http.Handler
		auth             bool
		want             int
	}{
		{"public discovery", "/api/admin/auth", "172.30.0.3:1234", s.publicHandler(), false, 404},
		{"public setup", "/api/admin/setup", "172.30.0.3:1234", s.publicHandler(), false, 404},
		{"public authenticated", "/api/admin/config", "172.30.0.3:1234", s.publicHandler(), true, 404},
		{"public encoded", "/api/%61dmin/config", "172.30.0.3:1234", s.publicHandler(), true, 404},
		{"public admin root", "/api/admin", "172.30.0.3:1234", s.publicHandler(), true, 404},
		{"public health", "/healthz", "172.30.0.3:1234", s.publicHandler(), false, 200},
		{"private wrong peer", "/api/admin/config", "172.30.0.3:1234", s.adminHandler(proxy), true, 404},
		{"private invalid peer", "/api/admin/config", "invalid", s.adminHandler(proxy), true, 404},
		{"private discovery", "/api/admin/auth", "172.30.0.131:1234", s.adminHandler(proxy), false, 200},
		{"private needs auth", "/api/admin/config", "172.30.0.131:1234", s.adminHandler(proxy), false, 401},
		{"private authenticated", "/api/admin/config", "172.30.0.131:1234", s.adminHandler(proxy), true, 200},
		{"private local health", "/healthz", "172.30.0.130:1234", s.adminHandler(proxy), false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Real-IP", proxy.String())
			r.Header.Set("X-Forwarded-For", proxy.String())
			r.Header.Set("Forwarded", "for="+proxy.String())
			if tc.auth {
				r.SetBasicAuth("admin", testAuthentication)
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}
	id := readyPackage(t, s)
	for _, handler := range []http.Handler{s.publicHandler(), s.adminHandler(proxy)} {
		r := httptest.NewRequest(http.MethodGet, "/api/packages/"+id, nil)
		r.RemoteAddr = "172.30.0.131:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("package availability: %d", w.Code)
		}
	}
}

func TestListenerConfig(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"PUBLIC_LISTEN_ADDR", ":8080"},
		{"PUBLIC_LISTEN_ADDR", "0.0.0.0:8080"},
		{"ADMIN_LISTEN_ADDR", "[::]:8081"},
		{"ADMIN_LISTEN_ADDR", "localhost:8081"},
		{"ADMIN_LISTEN_ADDR", "127.0.0.1:0"},
		{"ADMIN_LISTEN_ADDR", "127.0.0.1:8080"},
		{"ADMIN_PROXY_IP", "0.0.0.0"},
		{"ADMIN_PROXY_IP", "not-an-ip"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			t.Setenv("PUBLIC_LISTEN_ADDR", "127.0.0.1:8080")
			t.Setenv("ADMIN_LISTEN_ADDR", "127.0.0.1:8081")
			t.Setenv("ADMIN_PROXY_IP", "127.0.0.1")
			t.Setenv(tc.key, tc.value)
			if _, err := listenerConfigFromEnv(); err == nil {
				t.Fatal("unsafe listener configuration accepted")
			}
		})
	}
}

func TestServeListenersClosesBothOnShutdown(t *testing.T) {
	s := testServer(t)
	// Ephemeral ports are used only by this lifecycle test, not environment configuration.
	config := listenerConfig{publicAddr: "127.0.0.1:0", adminAddr: "127.0.0.1:0", adminProxy: net.ParseIP("127.0.0.1")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.serveListeners(ctx, config); err != nil {
		t.Fatal(err)
	}
}

func TestServeListenersFailsClosedWhenAdminBindFails(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	public, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := public.Addr().String()
	public.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	config := listenerConfig{publicAddr: addr, adminAddr: occupied.Addr().String(), adminProxy: net.ParseIP("127.0.0.1")}
	if err := testServer(t).serveListeners(ctx, config); err == nil {
		t.Fatal("admin bind failure must stop startup")
	}
	rebound, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("public listener leaked after failed startup: %v", err)
	}
	rebound.Close()
}

func TestListenerHealthRequiresBothListeners(t *testing.T) {
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) }))
	defer ready.Close()
	bad := httptest.NewServer(http.NotFoundHandler())
	defer bad.Close()
	config := listenerConfig{publicAddr: ready.Listener.Addr().String(), adminAddr: ready.Listener.Addr().String()}
	if err := config.healthCheck(); err != nil {
		t.Fatal(err)
	}
	config.adminAddr = bad.Listener.Addr().String()
	if err := config.healthCheck(); err == nil {
		t.Fatal("unhealthy admin listener was ignored")
	}
}
