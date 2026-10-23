package main

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type blockedUpload struct {
	body *io.PipeWriter
	done <-chan *httptest.ResponseRecorder
}

// startBlockedUpload sends a chunk whose body stalls until finish is called, as a slow
// tunnel would, and returns once the server has reserved quota and released s.mu.
func startBlockedUpload(t *testing.T, s *Server, id, token string, index string, size int64) blockedUpload {
	t.Helper()
	reader, writer := io.Pipe()
	r := httptest.NewRequest("PUT", "/api/admin/packages/"+id+"/chunks/"+index, reader)
	r.ContentLength = size
	r.RemoteAddr = "192.0.2.55:1234"
	r.SetBasicAuth("admin", testAuthentication)
	r.Header.Set("X-Upload-Token", token)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		done <- w
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.mu.Lock()
		inFlight := s.packages[id].chunkInFlight
		s.mu.Unlock()
		if inFlight {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("upload never reached the unlocked write phase")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() { _ = writer.CloseWithError(io.ErrUnexpectedEOF) })
	return blockedUpload{body: writer, done: done}
}

func (u blockedUpload) finish(t *testing.T, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	go func() {
		_, _ = u.body.Write(data)
		_ = u.body.Close()
	}()
	select {
	case w := <-u.done:
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not complete")
		return nil
	}
}

func within(t *testing.T, what string, fn func() int) int {
	t.Helper()
	result := make(chan int, 1)
	go func() { result <- fn() }()
	select {
	case code := <-result:
		return code
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked behind a slow upload", what)
		return 0
	}
}

func TestSlowUploadDoesNotBlockOtherRequests(t *testing.T) {
	s := testServer(t)
	ready := readyPackage(t, s)
	id, token := createPackage(t, s)
	upload := startBlockedUpload(t, s, id, token, "0", 32)

	if code := within(t, "recipient metadata", func() int { return request(s, "GET", "/api/packages/"+ready, nil, false, "").Code }); code != 200 {
		t.Fatal("metadata during upload", code)
	}
	if code := within(t, "admin listing", func() int { return request(s, "GET", "/api/admin/packages", nil, true, "").Code }); code != 200 {
		t.Fatal("listing during upload", code)
	}
	if code := within(t, "recipient claim", func() int { return directClaim(s, ready, downloadClaimTokenFixture, nil).Code }); code != 200 {
		t.Fatal("claim during upload", code)
	}
	if err := within(t, "expiry sweep", func() int {
		if s.sweep() != nil {
			return 1
		}
		return 0
	}); err != 0 {
		t.Fatal("sweep failed during upload")
	}
	if used, _ := storageStats(t, s); used != 32 {
		t.Fatalf("in-flight chunk not reserved against quota: %d", used)
	}
	if w := request(s, "PUT", "/api/admin/packages/"+id+"/chunks/0", bytes.Repeat([]byte{1}, 32), true, token); w.Code != 409 {
		t.Fatal("concurrent chunk for the same package accepted", w.Code)
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(1), true, token); w.Code != 409 {
		t.Fatal("finalize accepted while a chunk is in flight", w.Code)
	}

	if w := upload.finish(t, bytes.Repeat([]byte{1}, 32)); w.Code != 204 {
		t.Fatal("slow upload failed", w.Code, w.Body)
	}
	if p := s.packages[id]; p.Chunks != 1 || p.Bytes != 32 || p.chunkInFlight || s.reservedBytes != 0 {
		t.Fatalf("commit state: chunks %d bytes %d inFlight %v reserved %d", p.Chunks, p.Bytes, p.chunkInFlight, s.reservedBytes)
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(1), true, token); w.Code != 204 {
		t.Fatal("finalize after upload", w.Code, w.Body)
	}
}

func TestReservationsEnforceQuotaAcrossConcurrentUploads(t *testing.T) {
	s := testServer(t)
	first, firstToken := createPackage(t, s)
	second, secondToken := createPackage(t, s)
	s.quota = 48
	upload := startBlockedUpload(t, s, first, firstToken, "0", 32)
	if w := request(s, "PUT", "/api/admin/packages/"+second+"/chunks/0", bytes.Repeat([]byte{2}, 32), true, secondToken); w.Code != 413 {
		t.Fatal("concurrent uploads overcommitted the quota", w.Code)
	}
	if w := upload.finish(t, bytes.Repeat([]byte{1}, 32)); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request(s, "PUT", "/api/admin/packages/"+second+"/chunks/0", bytes.Repeat([]byte{2}, 16), true, secondToken); w.Code != 204 {
		t.Fatal("released reservation was not returned", w.Code, w.Body)
	}
}

func TestBodyLongerThanDeclaredLengthIsRejected(t *testing.T) {
	s := testServer(t)
	id, token := createPackage(t, s)
	upload := startBlockedUpload(t, s, id, token, "0", 16)
	if w := upload.finish(t, bytes.Repeat([]byte{1}, 32)); w.Code != 413 {
		t.Fatal("body exceeded its reservation", w.Code)
	}
	if p := s.packages[id]; p.Chunks != 0 || p.Bytes != 0 || s.reservedBytes != 0 {
		t.Fatal("oversized body was committed")
	}
	if _, err := os.Stat(s.chunk(id, 0) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("rejected body left a temporary file", err)
	}
}

func TestPackageRemovedDuringUploadDiscardsChunk(t *testing.T) {
	for _, removal := range []string{"delete", "expire"} {
		t.Run(removal, func(t *testing.T) {
			s := testServer(t)
			id, token := createPackage(t, s)
			upload := startBlockedUpload(t, s, id, token, "0", 32)
			if removal == "delete" {
				if code := within(t, "delete", func() int { return request(s, "DELETE", "/api/admin/packages/"+id, nil, true, "").Code }); code != 204 {
					t.Fatal("delete during upload", code)
				}
			} else {
				expiresAt := s.packages[id].ExpiresAt
				s.mu.Lock()
				s.now = func() time.Time { return expiresAt }
				s.mu.Unlock()
				if err := s.sweep(); err != nil {
					t.Fatal(err)
				}
			}
			if w := upload.finish(t, bytes.Repeat([]byte{1}, 32)); w.Code != 409 {
				t.Fatal("chunk committed to a removed package", w.Code)
			}
			p := s.packages[id]
			if p.Chunks != 0 || p.Bytes != 0 || s.reservedBytes != 0 {
				t.Fatal("removed package retained upload state")
			}
			for _, name := range []string{s.chunk(id, 0), s.chunk(id, 0) + ".tmp"} {
				if _, err := os.Stat(name); !os.IsNotExist(err) {
					t.Fatal("ciphertext survived removal", name, err)
				}
			}
		})
	}
}
