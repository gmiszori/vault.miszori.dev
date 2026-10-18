package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type shortReadDeadlineWriter struct {
	http.ResponseWriter
	timeout time.Duration
}

func (w *shortReadDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *shortReadDeadlineWriter) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(w.timeout)
	}
	return http.NewResponseController(w.ResponseWriter).SetReadDeadline(deadline)
}

func TestRejectedBodyDoesNotHoldAConnectionOpen(t *testing.T) {
	s := testServer(t)
	server := httptest.NewServer(s)
	defer func() { server.CloseClientConnections(); server.Close() }()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprint(conn, "POST /api/admin/packages HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1024\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal("rejected request waited for its untrusted body", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized || !response.Close {
		t.Fatalf("unsafe rejection: %s, close=%v", response.Status, response.Close)
	}
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadOutlivesRequestBodyReadDeadline(t *testing.T) {
	s := testServer(t)
	id, token := createPackage(t, s)
	payload := bytes.Repeat([]byte{0x5a}, 8*1024*1024)
	const chunks = 3
	for n := 0; n < chunks; n++ {
		w := request(s, http.MethodPut, fmt.Sprintf("/api/admin/packages/%s/chunks/%d", id, n), payload, true, token)
		if w.Code != http.StatusNoContent {
			t.Fatalf("upload: %d %s", w.Code, w.Body)
		}
	}
	if w := request(s, http.MethodPost, "/api/admin/packages/"+id+"/finalize", finalizeBody(3), true, token); w.Code != http.StatusNoContent {
		t.Fatalf("finalize: %d %s", w.Code, w.Body)
	}
	const deadline = 100 * time.Millisecond
	finished := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		s.ServeHTTP(&shortReadDeadlineWriter{w, deadline}, r)
	}))
	defer func() { server.CloseClientConnections(); server.Close() }()
	client := server.Client()
	client.Timeout = 5 * time.Second
	claim, err := http.NewRequest(http.MethodPost, server.URL+"/api/packages/"+id+"/consume", nil)
	if err != nil {
		t.Fatal(err)
	}
	claim.Header.Set("X-Claim-Token", downloadClaimTokenFixture)
	response, err := client.Do(claim)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal(response.Status)
	}
	first := make([]byte, 1)
	if _, err = io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	// A paused receiver keeps the real TCP response open past the shortened body deadline.
	time.Sleep(3 * deadline)
	received, err := io.Copy(io.Discard, response.Body)
	expected := int64(chunks * (len(payload) + 4))
	if err != nil || received+1 != expected {
		t.Fatalf("slow download truncated after body read deadline: received %d/%d bytes: %v", received+1, expected, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.packages[id].Status != "consumed" {
		t.Fatalf("status: %s", s.packages[id].Status)
	}
}
