package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type listenerConfig struct {
	publicAddr string
	adminAddr  string
	adminProxy net.IP
}

func listenerConfigFromEnv() (listenerConfig, error) {
	config := listenerConfig{
		publicAddr: env("PUBLIC_LISTEN_ADDR", "127.0.0.1:8080"),
		adminAddr:  env("ADMIN_LISTEN_ADDR", "127.0.0.1:8081"),
		adminProxy: net.ParseIP(env("ADMIN_PROXY_IP", "127.0.0.1")),
	}
	for _, addr := range []string{config.publicAddr, config.adminAddr} {
		host, port, err := net.SplitHostPort(addr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.IsUnspecified() || port == "0" || port == "" {
			return config, fmt.Errorf("listeners require specific IP addresses and nonzero ports")
		}
	}
	if config.publicAddr == config.adminAddr || config.adminProxy == nil || config.adminProxy.IsUnspecified() {
		return config, fmt.Errorf("listeners must differ and ADMIN_PROXY_IP must be a specific IP")
	}
	return config, nil
}

func (s *Server) publicHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin" || strings.HasPrefix(r.URL.Path, "/api/admin/") {
			fail(w, http.StatusNotFound, "Not found")
			return
		}
		s.ServeHTTP(w, r)
	})
}

func (s *Server) adminHandler(proxy net.IP) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		// Use the socket peer, never client-controlled forwarding headers.
		if r.URL.Path != "/healthz" && (err != nil || !proxy.Equal(net.ParseIP(host))) {
			fail(w, http.StatusNotFound, "Not found")
			return
		}
		s.ServeHTTP(w, r)
	})
}

func (c listenerConfig) healthCheck() error {
	for _, addr := range []string{c.publicAddr, c.adminAddr} {
		if err := healthCheck("http://" + addr + "/healthz"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) serveListeners(ctx context.Context, config listenerConfig) error {
	servers := []*http.Server{
		{Addr: config.publicAddr, Handler: s.publicHandler()},
		{Addr: config.adminAddr, Handler: s.adminHandler(config.adminProxy)},
	}
	listeners := make([]net.Listener, 0, len(servers))
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	// Bind both interfaces before accepting any traffic; no single-listener fallback.
	for _, server := range servers {
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}
	results := make(chan error, len(servers))
	for i, server := range servers {
		server.ReadHeaderTimeout = 10 * time.Second
		server.IdleTimeout = time.Minute
		server.MaxHeaderBytes = 16384
		go func(server *http.Server, listener net.Listener) {
			results <- server.Serve(s.gate.limitListener(listener))
		}(server, listeners[i])
	}
	var serveErr error
	completed := 0
	select {
	case <-ctx.Done():
	case serveErr = <-results:
		completed++
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Go(func() {
			if err := server.Shutdown(shutdown); err != nil {
				_ = server.Close()
			}
		})
	}
	wg.Wait()
	for completed < len(servers) {
		err := <-results
		if serveErr == nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
		completed++
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
