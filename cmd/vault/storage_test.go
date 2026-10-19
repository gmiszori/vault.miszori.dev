package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func storageStats(t *testing.T, s *Server) (int64, int64) {
	t.Helper()
	w := request(s, "GET", "/api/admin/packages", nil, true, "")
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var data struct {
		Storage struct {
			UsedBytes int64 `json:"usedBytes"`
			MaxBytes  int64 `json:"maxBytes"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	return data.Storage.UsedBytes, data.Storage.MaxBytes
}

func TestStorageStatsTrackQuotaLifecycle(t *testing.T) {
	s := testServer(t)
	check := func(want int64) {
		t.Helper()
		used, max := storageStats(t, s)
		if used != want || max != s.quota {
			t.Fatalf("storage = %d/%d, want %d/%d", used, max, want, s.quota)
		}
	}
	check(0)
	id, token := createPackage(t, s)
	w := request(s, "PUT", "/api/admin/packages/"+id+"/chunks/0", bytes.Repeat([]byte{1}, 32), true, token)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	check(32)
	w = request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(1), true, token)
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	check(32)
	w = request(s, "POST", "/api/packages/"+id+"/consume", nil, false, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	check(0)
	id = readyPackage(t, s)
	check(64)
	w = request(s, "DELETE", "/api/admin/packages/"+id, nil, true, "")
	if w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	check(0)
}

func TestSweepRetriesCleanupAndRetainsQuota(t *testing.T) {
	for _, failure := range []string{"metadata", "delete"} {
		t.Run(failure, func(t *testing.T) {
			s := testServer(t)
			id := reusablePackage(t, s)
			p := s.packages[id]
			s.quota = p.Bytes
			var recoverStorage func() error
			if failure == "metadata" {
				blocked := filepath.Join(s.dir(id), "meta.json.tmp")
				if err := os.Mkdir(blocked, 0700); err != nil {
					t.Fatal(err)
				}
				recoverStorage = func() error { return os.Remove(blocked) }
			} else {
				blocked := s.chunk(id, 0)
				if err := os.Rename(blocked, blocked+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(blocked, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(blocked+".saved", filepath.Join(blocked, "ciphertext")); err != nil {
					t.Fatal(err)
				}
				probe := filepath.Join(blocked, "permission-probe")
				if err := os.WriteFile(probe, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(blocked, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(blocked, 0700) })
				if err := os.Remove(probe); err == nil {
					t.Skip("requires directory permissions to be enforced (drop DAC_OVERRIDE/DAC_READ_SEARCH when running as root)")
				}
				recoverStorage = func() error { return os.Chmod(blocked, 0700) }
			}
			s.now = func() time.Time { return p.ExpiresAt }
			for attempt := 0; attempt < 2; attempt++ {
				if err := s.sweep(); err == nil {
					t.Fatal("expiry cleanup did not report storage failure", attempt)
				}
				if p.Status != "expired" || directClaim(s, id, downloadClaimTokenFixture, nil).Code != 404 {
					t.Fatal("cleanup failure resurrected expired package")
				}
				if used, _ := storageStats(t, s); used != p.Bytes {
					t.Fatalf("cleanup failure released ciphertext quota: %d, want %d", used, p.Bytes)
				}
			}
			uploadID, token := createPackage(t, s)
			upload := "/api/admin/packages/" + uploadID + "/chunks/0"
			if w := request(s, "PUT", upload, bytes.Repeat([]byte{1}, 32), true, token); w.Code != 413 {
				t.Fatal("pending ciphertext cleanup bypassed quota", w.Code)
			}
			if err := recoverStorage(); err != nil {
				t.Fatal(err)
			}
			if err := s.sweep(); err != nil {
				t.Fatal("cleanup did not recover", err)
			}
			if _, err := os.Stat(s.chunk(id, 0)); !os.IsNotExist(err) {
				t.Fatal("sweep retry left ciphertext", err)
			}
			if used, _ := storageStats(t, s); used != 0 {
				t.Fatal("completed cleanup retained quota", used)
			}
			if w := request(s, "PUT", upload, bytes.Repeat([]byte{1}, 32), true, token); w.Code != 204 {
				t.Fatal("cleanup recovery did not release upload quota", w.Code)
			}
			restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
			if err != nil || restarted.packages[id].Status != "expired" {
				t.Fatal("expiry not durable after recovery", err)
			}
		})
	}
}

func TestSweepRetriesTerminalCleanup(t *testing.T) {
	for _, status := range []string{"deleted", "failed", "consumed"} {
		t.Run(status, func(t *testing.T) {
			s := testServer(t)
			id := readyPackage(t, s)
			p := s.packages[id]
			blocked := filepath.Join(s.dir(id), "meta.json.tmp")
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.purge(p, status); err == nil {
				t.Fatal("metadata obstruction did not prevent cleanup")
			}
			if err := os.Remove(blocked); err != nil {
				t.Fatal(err)
			}
			if err := s.sweep(); err != nil {
				t.Fatal(err)
			}
			if p.Status != status {
				t.Fatal("cleanup retry changed terminal status", p.Status)
			}
			if _, err := os.Stat(s.chunk(id, 0)); !os.IsNotExist(err) {
				t.Fatal("terminal cleanup retry retained ciphertext", err)
			}
			if used, _ := storageStats(t, s); used != 0 {
				t.Fatal("terminal cleanup retry retained quota", used)
			}
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			if err := s.sweep(); err != nil {
				t.Fatal("successful cleanup retried unnecessarily", err)
			}
		})
	}
}

func TestSweepDoesNotRetryCleanupDuringActiveReads(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	writer, done := startPausedRetrieval(t, s, id)
	defer func() { close(writer.release); <-done }()
	p := s.packages[id]
	blocked := filepath.Join(s.dir(id), "meta.json.tmp")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.now = func() time.Time { return p.ExpiresAt }
	s.mu.Unlock()
	if err := s.sweep(); err == nil {
		t.Fatal("expiry metadata obstruction not detected")
	}
	if err := s.sweep(); err != nil {
		t.Fatal("cleanup retried before admitted stream completed", err)
	}
	if _, err := os.Stat(s.chunk(id, 1)); err != nil {
		t.Fatal("sweep removed ciphertext needed by admitted stream", err)
	}
	if used, _ := storageStats(t, s); used != p.Bytes {
		t.Fatal("active stream ciphertext not counted", used)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
}

func TestStorageStatsCountOnlyQuotaHoldingStates(t *testing.T) {
	s := testServer(t)
	for _, status := range []string{"uploading", "ready", "consuming", "consumed", "failed", "expired", "deleted"} {
		s.packages[status] = &Package{ID: status, Status: status, Bytes: 100}
	}
	used, max := storageStats(t, s)
	if used != 300 || max != s.quota {
		t.Fatalf("storage = %d/%d, want 300/%d", used, max, s.quota)
	}
	if w := request(s, "GET", "/api/admin/packages", nil, false, ""); w.Code != 401 {
		t.Fatalf("unauthenticated stats: %d", w.Code)
	}
}
