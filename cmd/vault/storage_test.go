package main

import (
	"bytes"
	"encoding/json"
	"testing"
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
