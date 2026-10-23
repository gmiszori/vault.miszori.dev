package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type gateLimits struct {
	maxRequests           int
	maxDownloads          int
	maxUploads            int
	maxConnections        int
	publicPerMinute       int
	authFailuresPerMinute int
}

func defaultGateLimits() gateLimits {
	return gateLimits{64, 4, 2, 128, 600, 60}
}

func gateLimitsFromEnv() (gateLimits, error) {
	limits := defaultGateLimits()
	for _, setting := range []struct {
		name  string
		value *int
		max   int
	}{
		{"MAX_CONCURRENT_REQUESTS", &limits.maxRequests, 4096},
		{"MAX_CONCURRENT_DOWNLOADS", &limits.maxDownloads, 4096},
		{"MAX_CONCURRENT_UPLOADS", &limits.maxUploads, 4096},
		{"MAX_BACKEND_CONNECTIONS", &limits.maxConnections, 4096},
		{"PUBLIC_REQUESTS_PER_MINUTE", &limits.publicPerMinute, 1_000_000},
		{"AUTH_FAILURES_PER_MINUTE", &limits.authFailuresPerMinute, 1_000_000},
	} {
		if raw, exists := os.LookupEnv(setting.name); exists {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 || value > setting.max {
				return limits, fmt.Errorf("%s must be an integer between 1 and %d", setting.name, setting.max)
			}
			*setting.value = value
		}
	}
	if limits.maxDownloads > limits.maxRequests || limits.maxUploads > limits.maxRequests || limits.maxRequests > limits.maxConnections {
		return limits, fmt.Errorf("download and upload limits must not exceed requests; requests must not exceed connections")
	}
	return limits, nil
}

type minuteBucket struct {
	mu          sync.Mutex
	start       time.Time
	initialized bool
	count       int
}

func (b *minuteBucket) allow(now time.Time, limit int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	minute := now.Truncate(time.Minute)
	// A backwards clock must not replenish an exhausted budget.
	if !b.initialized || minute.After(b.start) {
		b.start, b.count, b.initialized = minute, 0, true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

type requestGate struct {
	limits         gateLimits
	requests       chan struct{}
	downloads      chan struct{}
	uploads        chan struct{}
	publicFailures minuteBucket
	adminDiscovery minuteBucket
	authFailures   minuteBucket
}

func newRequestGate(limits gateLimits) *requestGate {
	return &requestGate{
		limits:    limits,
		requests:  make(chan struct{}, limits.maxRequests),
		downloads: make(chan struct{}, limits.maxDownloads),
		uploads:   make(chan struct{}, limits.maxUploads),
	}
}

func (g *requestGate) acquire(r *http.Request) (release func(), ok bool) {
	slots := []chan struct{}{g.requests}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method == http.MethodPost && len(parts) == 4 && parts[0] == "api" && parts[1] == "packages" && parts[2] != "" && parts[3] == "consume" {
		slots = append(slots, g.downloads)
	}
	if r.Method == http.MethodPut && len(parts) == 6 && parts[0] == "api" && parts[1] == "admin" && parts[2] == "packages" && parts[3] != "" && parts[4] == "chunks" && parts[5] != "" {
		slots = append(slots, g.uploads)
	}
	for i, slot := range slots {
		select {
		case slot <- struct{}{}:
		default:
			for _, acquired := range slots[:i] {
				<-acquired
			}
			return nil, false
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, slot := range slots {
				<-slot
			}
		})
	}, true
}

func (g *requestGate) allowPublicFailure(now time.Time) bool {
	return g.publicFailures.allow(now, g.limits.publicPerMinute)
}

func (g *requestGate) allowAdminDiscovery(now time.Time) bool {
	return g.adminDiscovery.allow(now, g.limits.publicPerMinute)
}

func (g *requestGate) allowAuthFailure(now time.Time) bool {
	return g.authFailures.allow(now, g.limits.authFailuresPerMinute)
}

type gatedListener struct {
	net.Listener
	slots    chan struct{}
	done     chan struct{}
	once     sync.Once
	closeErr error
}

func (g *requestGate) limitListener(listener net.Listener) net.Listener {
	return &gatedListener{Listener: listener, slots: make(chan struct{}, g.limits.maxConnections), done: make(chan struct{})}
}

func (l *gatedListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case l.slots <- struct{}{}:
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		<-l.slots
		return nil, err
	}
	select {
	case <-l.done:
		conn.Close()
		<-l.slots
		return nil, net.ErrClosed
	default:
	}
	return &gatedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

func (l *gatedListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type gatedConn struct {
	net.Conn
	once     sync.Once
	release  func()
	closeErr error
}

func (c *gatedConn) Close() error {
	c.once.Do(func() {
		defer c.release()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}
