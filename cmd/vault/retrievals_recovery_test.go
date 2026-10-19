package main

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRetrievalMetadataFailureBeforeBytes(t *testing.T) {
	for _, oneTime := range []bool{false, true} {
		t.Run(fmt.Sprintf("oneTime=%v", oneTime), func(t *testing.T) {
			s := testServer(t)
			id := reusablePackage(t, s)
			p := s.packages[id]
			p.OneTime = oneTime
			if err := s.save(p); err != nil {
				t.Fatal(err)
			}
			blocked := filepath.Join(s.dir(id), "meta.json.tmp")
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			w := directClaim(s, id, downloadClaimTokenFixture, nil)
			if w.Code != 500 || w.Header().Get("Content-Type") == "application/octet-stream" {
				t.Fatal("metadata error served ciphertext", w.Code)
			}
			page := auditPage(t, s, id, "")
			if len(page.Retrievals) != 1 || p.RetrievalCount != 1 || p.OpenedAt == nil || !page.Retrievals[0].OpenedAt.Equal(*p.OpenedAt) || page.Retrievals[0].OpenedIP != p.OpenedIP {
				t.Fatal("metadata failure lost durable attempted retrieval", page)
			}
			if err := os.Remove(blocked); err != nil {
				t.Fatal(err)
			}
			if err := s.sweep(); err != nil {
				t.Fatal(err)
			}
			if oneTime {
				if p.Status != "failed" || directClaim(s, id, downloadClaimTokenFixture, nil).Code != 404 {
					t.Fatal("one-time metadata failure did not fail closed")
				}
				if _, err := os.Stat(s.chunk(id, 0)); !os.IsNotExist(err) {
					t.Fatal("one-time failure left ciphertext after cleanup retry", err)
				}
			} else {
				if p.Status != "ready" {
					t.Fatal("reusable metadata failure revoked valid package", p.Status)
				}
				if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 || w.Body.Len() != 72 {
					t.Fatal("reusable metadata failure prevented retry", w.Code)
				}
				if p.RetrievalCount != 2 || len(auditPage(t, s, id, "").Retrievals) != 2 {
					t.Fatal("retry lost or duplicated durable audit entries")
				}
			}
			restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
			if err != nil || restarted.packages[id].Status != p.Status || restarted.packages[id].RetrievalCount != p.RetrievalCount {
				t.Fatal("metadata recovery lost package or durable audit", err)
			}
		})
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
