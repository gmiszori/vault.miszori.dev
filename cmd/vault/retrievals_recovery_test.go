package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRetrievalMetadataFailureBeforeBytes(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	blocked := filepath.Join(s.dir(id), "meta.json.tmp")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	w := directClaim(s, id, downloadClaimTokenFixture, nil)
	if w.Code != 500 || w.Header().Get("Content-Type") == "application/octet-stream" {
		t.Fatal("metadata error served ciphertext", w.Code)
	}
	if len(auditPage(t, s, id, "").Retrievals) != 1 {
		t.Fatal("metadata failure lost durable attempted retrieval")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
}

func TestRetrievalRestartRepairsLaggingCountRejectsLostAudit(t *testing.T) {
	for _, damage := range []string{"stale-count", "missing", "truncated", "torn-record"} {
		t.Run(damage, func(t *testing.T) {
			s := testServer(t)
			id := reusablePackage(t, s)
			for i := 0; i < 2; i++ {
				if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
					t.Fatal(w.Code)
				}
			}
			path := filepath.Join(s.dir(id), retrievalLogName)
			switch damage {
			case "stale-count":
				s.packages[id].RetrievalCount = 0
				if err := s.save(s.packages[id]); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 500 {
					t.Fatal("missing log did not fail closed", w.Code)
				}
				if w := request(s, "GET", "/api/admin/packages/"+id+"/retrievals", nil, true, ""); w.Code != 500 {
					t.Fatal("missing log silently fell back to last retrieval", w.Code)
				}
			case "truncated":
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Truncate(path, int64(bytes.IndexByte(data, '\n')+1)); err != nil {
					t.Fatal(err)
				}
			case "torn-record":
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(`{"openedAt":`)
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
			if damage == "stale-count" {
				if err != nil || restarted.packages[id].RetrievalCount != 2 {
					t.Fatal("crash-lagging metadata count not repaired", err)
				}
			} else if err == nil {
				t.Fatal("restart accepted lost/corrupt audit")
			}
		})
	}
}

func TestRetrievalAuditRejectsCrossOrigin(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	r := httptest.NewRequest("GET", "/api/admin/packages/"+id+"/retrievals", nil)
	r.SetBasicAuth("admin", testAuthentication)
	r.Header.Set("Origin", "https://other.example")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin audit allowed", w.Code)
	}
}
