package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateLimitsEnvironment(t *testing.T) {
	names := []string{"MAX_CONCURRENT_REQUESTS", "MAX_CONCURRENT_DOWNLOADS", "MAX_CONCURRENT_UPLOADS", "MAX_BACKEND_CONNECTIONS", "PUBLIC_REQUESTS_PER_MINUTE", "AUTH_FAILURES_PER_MINUTE"}
	for _, name := range names {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	want := gateLimits{64, 4, 2, 128, 600, 60}
	if got, err := gateLimitsFromEnv(); err != nil || got != want || defaultGateLimits() != want {
		t.Fatalf("defaults: %+v, %v", got, err)
	}
	for i, name := range names {
		maximum := "4096"
		if i >= 4 {
			maximum = "1000000"
		}
		for _, value := range []string{"", "0", "-1", "one", "1.5", " 2", "2 ", "99999999999999999999999999999", maximum + "0"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				t.Setenv(name, value)
				if _, err := gateLimitsFromEnv(); err == nil {
					t.Fatalf("accepted %s=%q", name, value)
				}
			})
		}
	}
	for _, values := range []map[string]string{
		{"MAX_CONCURRENT_DOWNLOADS": "65"},
		{"MAX_CONCURRENT_UPLOADS": "65"},
		{"MAX_BACKEND_CONNECTIONS": "63"},
	} {
		t.Run(fmt.Sprint(values), func(t *testing.T) {
			for name, value := range values {
				t.Setenv(name, value)
			}
			if _, err := gateLimitsFromEnv(); err == nil {
				t.Fatal("inconsistent limits accepted")
			}
		})
	}
	for i, name := range names {
		value := "4096"
		if i >= 4 {
			value = "1000000"
		}
		t.Setenv(name, value)
	}
	if _, err := gateLimitsFromEnv(); err != nil {
		t.Fatalf("maximum limits rejected: %v", err)
	}
	for _, name := range names {
		t.Setenv(name, "1")
	}
	if _, err := gateLimitsFromEnv(); err != nil {
		t.Fatalf("minimum limits rejected: %v", err)
	}
}

func gateRequest(method, path, ip string) *httpRequestForGate {
	return &httpRequestForGate{method: method, path: path, ip: ip}
}

type httpRequestForGate struct {
	method, path, ip string
}

func (r *httpRequestForGate) acquire(g *requestGate) (func(), bool) {
	req := httptest.NewRequest(r.method, r.path, nil)
	req.RemoteAddr = r.ip
	return g.acquire(req)
}

func TestRequestGateSlotsAndRecovery(t *testing.T) {
	limits := defaultGateLimits()
	limits.maxRequests, limits.maxDownloads, limits.maxUploads = 3, 1, 1
	g := newRequestGate(limits)
	download, ok := gateRequest("POST", "/api/packages/first/consume", "192.0.2.1:1").acquire(g)
	if !ok {
		t.Fatal("first download rejected")
	}
	defer download()
	for i := 0; i < 100; i++ {
		if release, ok := gateRequest("POST", "/api/packages/other/consume", "192.0.2.2:2").acquire(g); ok || release != nil {
			t.Fatal("global download capacity bypassed")
		}
		if len(g.requests) != 1 || len(g.downloads) != 1 {
			t.Fatal("failed download leaked slots")
		}
	}
	upload, ok := gateRequest("PUT", "/api/admin/packages/first/chunks/0", "192.0.2.1:1").acquire(g)
	if !ok {
		t.Fatal("independent upload slot rejected")
	}
	defer upload()
	if release, ok := gateRequest("PUT", "/api/admin/packages/second/chunks/1", "192.0.2.3:3").acquire(g); ok || release != nil || len(g.requests) != 2 {
		t.Fatal("upload rejection leaked or bypassed capacity")
	}
	ordinary, ok := gateRequest("GET", "/api/admin/packages", "192.0.2.4:4").acquire(g)
	if !ok {
		t.Fatal("ordinary request rejected")
	}
	defer ordinary()
	if release, ok := gateRequest("GET", "/api/packages/other", "192.0.2.5:5").acquire(g); ok || release != nil {
		t.Fatal("request limit bypassed")
	}
	download()
	download()
	if len(g.requests) != 2 || len(g.downloads) != 0 {
		t.Fatal("double release corrupted slots")
	}
	recovered, ok := gateRequest("POST", "/api/packages/other/consume", "192.0.2.2:2").acquire(g)
	if !ok {
		t.Fatal("download slot not recovered")
	}
	recovered()
	upload()
	ordinary()
	if len(g.requests)+len(g.downloads)+len(g.uploads) != 0 {
		t.Fatal("active slots remain")
	}
}

func TestRequestGatePathClassification(t *testing.T) {
	for _, tc := range []struct {
		method, path     string
		download, upload int
	}{
		{"POST", "/api/packages/x/consume", 1, 0},
		{"POST", "/api/packages/x/consume/", 1, 0},
		{"POST", "//api/packages/x/consume//", 1, 0},
		{"PUT", "/api/admin/packages/x/chunks/0", 0, 1},
		{"GET", "/api/packages/x/consume", 0, 0},
		{"POST", "/api/packages/x/consume/extra", 0, 0},
		{"POST", "/api/packages//consume", 0, 0},
		{"PUT", "/api/admin/packages/x/chunks/", 0, 0},
		{"PUT", "/api/admin/packages/x/chunks/0/extra", 0, 0},
		{"POST", "/api/admin/packages/x/chunks/0", 0, 0},
		{"PUT", "/api/admin/packages/x", 0, 0},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			g := newRequestGate(defaultGateLimits())
			release, ok := gateRequest(tc.method, tc.path, "192.0.2.1:1").acquire(g)
			if !ok {
				t.Fatal("request rejected")
			}
			defer release()
			if len(g.requests) != 1 || len(g.downloads) != tc.download || len(g.uploads) != tc.upload {
				t.Fatal("incorrect slot classification")
			}
		})
	}
}

func TestRequestGateConcurrentRelease(t *testing.T) {
	g := newRequestGate(defaultGateLimits())
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				release, ok := gateRequest("POST", "/api/packages/x/consume", "192.0.2.1:1").acquire(g)
				if !ok {
					continue
				}
				var closers sync.WaitGroup
				for k := 0; k < 3; k++ {
					closers.Go(release)
				}
				closers.Wait()
			}
		})
	}
	wg.Wait()
	if len(g.requests)+len(g.downloads)+len(g.uploads) != 0 {
		t.Fatal("concurrent acquisition leaked slots")
	}
}

func TestRequestGateMinuteBuckets(t *testing.T) {
	limits := defaultGateLimits()
	limits.publicPerMinute, limits.authFailuresPerMinute = 2, 1
	g := newRequestGate(limits)
	now := time.Date(2026, 1, 1, 12, 0, 59, 0, time.UTC)
	if !g.allowPublicFailure(now) || !g.allowPublicFailure(now) || g.allowPublicFailure(now) {
		t.Fatal("public budget not enforced")
	}
	if !g.allowAuthFailure(now) || g.allowAuthFailure(now) {
		t.Fatal("independent auth budget not enforced")
	}
	for i := 0; i < 100; i++ {
		if g.allowPublicFailure(now.Add(-time.Hour)) || g.allowAuthFailure(now.Add(-time.Hour)) {
			t.Fatal("rewinding clock replenished budget")
		}
	}
	if g.publicFailures.count != 2 || g.authFailures.count != 1 {
		t.Fatal("rejected requests increased bucket counters")
	}
	now = now.Add(time.Second)
	if !g.allowPublicFailure(now) || !g.allowAuthFailure(now) {
		t.Fatal("fixed minute boundary did not replenish budgets")
	}
	if !g.allowPublicFailure(now.Add(-time.Hour)) || g.allowPublicFailure(now) {
		t.Fatal("backwards clock failed to retain current bucket")
	}
	if !g.allowPublicFailure(now.Add(24 * time.Hour)) {
		t.Fatal("forward clock failed to replenish budget")
	}
	zero := newRequestGate(limits)
	if !zero.allowPublicFailure(time.Time{}) || !zero.allowPublicFailure(time.Time{}) || zero.allowPublicFailure(time.Time{}) {
		t.Fatal("zero time repeatedly initialized bucket")
	}
}

func TestRequestGateConcurrentBudgetsAndChunkTraffic(t *testing.T) {
	limits := defaultGateLimits()
	limits.publicPerMinute, limits.authFailuresPerMinute = 23, 11
	g := newRequestGate(limits)
	now := time.Now()
	var public, failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			if g.allowPublicFailure(now) {
				public.Add(1)
			}
			if g.allowAuthFailure(now) {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if public.Load() != 23 || failures.Load() != 11 {
		t.Fatalf("concurrent budgets: %d, %d", public.Load(), failures.Load())
	}
	for i := 0; i < 2560; i++ {
		release, ok := gateRequest("PUT", fmt.Sprintf("/api/admin/packages/x/chunks/%d", i), "192.0.2.1:1").acquire(g)
		if !ok {
			t.Fatalf("authenticated chunk %d rate limited", i)
		}
		release()
	}
}

type gateAcceptResult struct {
	conn net.Conn
	err  error
}

type gateTestListener struct {
	incoming chan gateAcceptResult
	entered  chan struct{}
	done     chan struct{}
	once     sync.Once
}

func newGateTestListener(t *testing.T) *gateTestListener {
	t.Helper()
	l := &gateTestListener{incoming: make(chan gateAcceptResult, 32), entered: make(chan struct{}, 32), done: make(chan struct{})}
	t.Cleanup(func() { l.Close() })
	return l
}

func (l *gateTestListener) Accept() (net.Conn, error) {
	l.entered <- struct{}{}
	select {
	case result := <-l.incoming:
		return result.conn, result.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *gateTestListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *gateTestListener) Addr() net.Addr { return &net.TCPAddr{} }

func gateTestSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("listener operation timed out")
	}
}

func gateTestAccept(t *testing.T, l net.Listener) <-chan gateAcceptResult {
	t.Helper()
	result := make(chan gateAcceptResult, 1)
	go func() {
		conn, err := l.Accept()
		result <- gateAcceptResult{conn, err}
	}()
	return result
}

func gateTestResult(t *testing.T, result <-chan gateAcceptResult) gateAcceptResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("Accept timed out")
		return gateAcceptResult{}
	}
}

func TestGatedListenerCapacityRecoveryAndDoubleClose(t *testing.T) {
	limits := defaultGateLimits()
	limits.maxConnections = 1
	inner := newGateTestListener(t)
	listener := newRequestGate(limits).limitListener(inner)
	t.Cleanup(func() { listener.Close() })
	first, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	inner.incoming <- gateAcceptResult{conn: first}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	gateTestSignal(t, inner.entered)
	pending := gateTestAccept(t, listener)
	select {
	case <-inner.entered:
		t.Fatal("underlying Accept called above live connection limit")
	case <-time.After(30 * time.Millisecond):
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Go(func() { conn.Close() })
	}
	wg.Wait()
	gateTestSignal(t, inner.entered)
	second, peer2 := net.Pipe()
	t.Cleanup(func() { peer2.Close() })
	inner.incoming <- gateAcceptResult{conn: second}
	got := gateTestResult(t, pending)
	if got.err != nil {
		t.Fatal(got.err)
	}
	got.conn.Close()
	if len(listener.(*gatedListener).slots) != 0 {
		t.Fatal("connection close leaked capacity")
	}
}

func TestGatedListenerCloseUnblocksAccept(t *testing.T) {
	for _, capacityWait := range []bool{false, true} {
		t.Run(fmt.Sprint(capacityWait), func(t *testing.T) {
			limits := defaultGateLimits()
			limits.maxConnections = 1
			inner := newGateTestListener(t)
			listener := newRequestGate(limits).limitListener(inner)
			t.Cleanup(func() { listener.Close() })
			if capacityWait {
				first, peer := net.Pipe()
				t.Cleanup(func() { peer.Close() })
				inner.incoming <- gateAcceptResult{conn: first}
				conn, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				gateTestSignal(t, inner.entered)
			}
			pending := gateTestAccept(t, listener)
			if !capacityWait {
				gateTestSignal(t, inner.entered)
			} else {
				select {
				case <-inner.entered:
					t.Fatal("capacity-waiting Accept reached underlying listener")
				case <-time.After(30 * time.Millisecond):
				}
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if got := gateTestResult(t, pending); got.conn != nil || !errors.Is(got.err, net.ErrClosed) {
				t.Fatalf("Accept after Close: %+v", got)
			}
			if conn, err := listener.Accept(); conn != nil || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("new Accept after Close: %v, %v", conn, err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGatedListenerAcceptErrorReleasesCapacity(t *testing.T) {
	limits := defaultGateLimits()
	limits.maxConnections = 1
	inner := newGateTestListener(t)
	listener := newRequestGate(limits).limitListener(inner)
	t.Cleanup(func() { listener.Close() })
	wantErr := errors.New("accept failed")
	partial, partialPeer := net.Pipe()
	t.Cleanup(func() { partialPeer.Close() })
	inner.incoming <- gateAcceptResult{conn: partial, err: wantErr}
	if conn, err := listener.Accept(); conn != nil || !errors.Is(err, wantErr) {
		t.Fatalf("unexpected Accept result: %v, %v", conn, err)
	}
	partial.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := partial.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failed Accept left its partial connection open: %v", err)
	}
	if len(listener.(*gatedListener).slots) != 0 {
		t.Fatal("failed Accept leaked capacity")
	}
	server, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	inner.incoming <- gateAcceptResult{conn: server}
	got := gateTestResult(t, gateTestAccept(t, listener))
	if got.err != nil {
		t.Fatal(got.err)
	}
	got.conn.Close()
}
