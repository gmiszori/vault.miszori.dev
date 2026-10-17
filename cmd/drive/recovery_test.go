package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestInterruptedLabeledPackagesRetainPrivateMetadata(t *testing.T) {
	for _, status := range []string{"uploading", "consuming"} {
		t.Run(status, func(t *testing.T) {
			s := testServer(t)
			id := readyPackage(t, s)
			patchLabel(t, s, id, nameEnvelope(17))
			p := s.packages[id]
			p.Status = status
			if status == "consuming" {
				now := time.Now()
				p.OpenedAt = &now
				p.OpenedIP = "192.0.2.1"
				r := httptest.NewRequest("POST", "/", nil)
				r.Header.Set("User-Agent", "Firefox/130 Linux")
				p.OpenedBrowser = browserProfile(r)
			}
			if err := s.save(p); err != nil {
				t.Fatal(err)
			}
			restarted, err := newServer(s.root, s.user, s.password, s.origin, s.quota)
			if err != nil {
				t.Fatal(err)
			}
			got := restarted.packages[id]
			if got.Status != "failed" || got.EncryptedName == nil || *got.EncryptedName != *p.EncryptedName {
				t.Fatal("recovery lost label")
			}
			if status == "consuming" && (got.OpenedBrowser == nil || *got.OpenedBrowser != *p.OpenedBrowser || got.OpenedIP != p.OpenedIP || !got.OpenedAt.Equal(*p.OpenedAt)) {
				t.Fatal("recovery lost claim audit")
			}
			restarted.now = func() time.Time { return got.ExpiresAt.Add(90 * 24 * time.Hour) }
			if err := restarted.sweep(); err != nil {
				t.Fatal(err)
			}
			if restarted.packages[id] == nil {
				t.Fatal("private metadata removed before audit retention elapsed")
			}
		})
	}
}
