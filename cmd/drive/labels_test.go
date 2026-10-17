package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nameEnvelope(n int) *EncryptedName {
	return &EncryptedName{Version: 1, IV: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 12)), Ciphertext: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, n))}
}

func patchBody(name *EncryptedName) []byte {
	b, _ := json.Marshal(map[string]any{"encryptedName": name})
	return b
}

func patchLabel(t *testing.T, s *Server, id string, name *EncryptedName) {
	t.Helper()
	w := request(s, "PATCH", "/api/admin/packages/"+id, patchBody(name), true, "")
	if w.Code != 204 || w.Body.Len() != 0 {
		t.Fatalf("patch: %d %s", w.Code, w.Body)
	}
}

func TestLabelConfigAndSaltPersistence(t *testing.T) {
	s := testServer(t)
	path := "/api/admin/config"
	if w := request(s, "GET", path, nil, false, ""); w.Code != 401 {
		t.Fatal("public label configuration")
	}
	w := request(s, "GET", path, nil, true, "")
	var config struct {
		PublicOrigin string   `json:"publicOrigin"`
		LabelKey     LabelKey `json:"labelKey"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || config.PublicOrigin != s.origin || config.LabelKey.Version != 1 || config.LabelKey.Iterations != 600000 || !canonicalBase64(config.LabelKey.Salt, 16, 16) {
		t.Fatalf("bad config: %s", w.Body)
	}
	name := filepath.Join(s.root, "label-salt")
	b, err := os.ReadFile(name)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != config.LabelKey.Salt {
		t.Fatal("salt not persisted", err)
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("salt permissions", err)
	}
	id := readyPackage(t, s)
	patchLabel(t, s, id, nameEnvelope(17))
	restarted, err := newServer(s.root, "other-admin", "different-password-456", "https://new.example", s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.labelKey != s.labelKey || *restarted.packages[id].EncryptedName != *nameEnvelope(17) {
		t.Fatal("salt or label changed on restart/config change")
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".label-salt-") {
			t.Fatal("salt staging file retained")
		}
	}
}

func TestMissingOrInvalidLabelSaltFailsClosed(t *testing.T) {
	for _, status := range []string{"uploading", "ready", "consuming", "consumed", "expired", "deleted", "failed"} {
		t.Run(status, func(t *testing.T) {
			s := testServer(t)
			id := readyPackage(t, s)
			patchLabel(t, s, id, nameEnvelope(17))
			p := s.packages[id]
			p.Status = status
			p.ExpiresAt = time.Now().Add(-100 * 24 * time.Hour)
			if err := s.save(p); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(s.root, "label-salt")); err != nil {
				t.Fatal(err)
			}
			if _, err := newServer(s.root, s.user, s.password, s.origin, s.quota); err == nil {
				t.Fatal("missing salt silently regenerated")
			}
			after, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("startup mutated labeled records before detecting missing salt", err)
			}
			if _, err := os.Stat(filepath.Join(s.root, "label-salt")); !os.IsNotExist(err) {
				t.Fatal("missing salt was recreated")
			}
		})
	}
	for _, length := range []int{0, 15, 17, 32} {
		s := testServer(t)
		if err := os.WriteFile(filepath.Join(s.root, "label-salt"), make([]byte, length), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := newServer(s.root, s.user, s.password, s.origin, s.quota); err == nil {
			t.Fatalf("invalid salt length %d accepted", length)
		}
	}
}

func TestLegacyMetadataWithoutSaltOrNewFields(t *testing.T) {
	s := testServer(t)
	id := readyPackage(t, s)
	if err := os.Remove(filepath.Join(s.root, "label-salt")); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, s.user, s.password, s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	p := restarted.packages[id]
	if p.EncryptedName != nil || p.OpenedBrowser != nil || p.Status != "ready" || !canonicalBase64(restarted.labelKey.Salt, 16, 16) {
		t.Fatal("legacy package not readable")
	}
	w := request(restarted, "GET", "/api/admin/packages", nil, true, "")
	if bytes.Contains(w.Body.Bytes(), []byte("encryptedName")) || bytes.Contains(w.Body.Bytes(), []byte("openedBrowser")) {
		t.Fatal("optional fields not omitted")
	}
}

func TestEncryptedNameValidation(t *testing.T) {
	s := testServer(t)
	id, _ := createPackage(t, s)
	path := "/api/admin/packages/" + id
	patchLabel(t, s, id, nameEnvelope(17))
	valid := nameEnvelope(17)
	for _, size := range []int{17, 512} {
		patchLabel(t, s, id, nameEnvelope(size))
	}
	badNames := []*EncryptedName{}
	for _, size := range []int{0, 16, 513} {
		badNames = append(badNames, nameEnvelope(size))
	}
	for _, size := range []int{0, 11, 13} {
		n := *valid
		n.IV = base64.RawURLEncoding.EncodeToString(make([]byte, size))
		badNames = append(badNames, &n)
	}
	for _, version := range []int{0, 2, -1} {
		n := *valid
		n.Version = version
		badNames = append(badNames, &n)
	}
	for _, value := range []string{valid.Ciphertext + "=", valid.Ciphertext + "\n", strings.Repeat("+", 23), strings.Repeat("/", 23), strings.Repeat("A", 22) + "B", "not base64"} {
		n := *valid
		n.Ciphertext = value
		badNames = append(badNames, &n)
	}
	n := *valid
	n.IV += "\n"
	badNames = append(badNames, &n)
	bodies := []string{`{}`, `null`, `{"name":"plaintext"}`, `{"encryptedName":"plaintext"}`, `{"encryptedName":{}}`, `{"encryptedName":[],"passphrase":"secret"}`, `{"encryptedName":null,"name":"plaintext"}`, `{"encryptedName":null} {}`, `{"encryptedName":null,"passphrase":"secret"}`, `{"encryptedName":{"version":1,"iv":"` + valid.IV + `","ciphertext":"` + valid.Ciphertext + `","extra":true}}`, strings.Repeat(" ", 4097) + `{"encryptedName":null}`}
	for _, bad := range badNames {
		bodies = append(bodies, string(patchBody(bad)))
	}
	for _, body := range bodies {
		w := request(s, "PATCH", path, []byte(body), true, "")
		if w.Code != 400 || *s.packages[id].EncryptedName != *nameEnvelope(512) {
			t.Fatalf("invalid body accepted or mutated state: %s: %d", body, w.Code)
		}
	}
	patchLabel(t, s, id, nil)
	if s.packages[id].EncryptedName != nil {
		t.Fatal("clear failed")
	}
	if request(s, "PATCH", "/api/admin/packages/"+strings.Repeat("a", 64), patchBody(valid), true, "").Code != 404 {
		t.Fatal("missing package patched")
	}
}

func TestEncryptedNameAuthAndOrigins(t *testing.T) {
	s := testServer(t)
	id, _ := createPackage(t, s)
	path := "/api/admin/packages/" + id
	if request(s, "PATCH", path, patchBody(nameEnvelope(17)), false, "").Code != 401 {
		t.Fatal("unauthenticated patch accepted")
	}
	for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
		r := httptest.NewRequest("PATCH", path, bytes.NewReader(patchBody(nameEnvelope(17))))
		r.SetBasicAuth(s.user, s.password)
		value := "https://evil.example"
		if header == "Sec-Fetch-Site" {
			value = "cross-site"
		}
		r.Header.Set(header, value)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 || s.packages[id].EncryptedName != nil {
			t.Fatal("cross-origin patch accepted")
		}
	}
}

func TestEncryptedNameHistoricalStatesAndSaveFailure(t *testing.T) {
	for _, status := range []string{"uploading", "ready", "consuming", "consumed", "expired", "deleted", "failed"} {
		t.Run(status, func(t *testing.T) {
			s := testServer(t)
			id, _ := createPackage(t, s)
			s.packages[id].Status = status
			s.packages[id].ExpiresAt = time.Now().Add(-time.Hour)
			patchLabel(t, s, id, nameEnvelope(17))
			if s.packages[id].Status != status {
				t.Fatal("label altered lifecycle")
			}
			patchLabel(t, s, id, nil)
		})
	}
	s := testServer(t)
	id, _ := createPackage(t, s)
	patchLabel(t, s, id, nameEnvelope(17))
	before, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.dir(id), "meta.json.tmp"), 0700); err != nil {
		t.Fatal(err)
	}
	w := request(s, "PATCH", "/api/admin/packages/"+id, patchBody(nameEnvelope(32)), true, "")
	after, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
	if w.Code != 500 || err != nil || !bytes.Equal(before, after) || *s.packages[id].EncryptedName != *nameEnvelope(17) {
		t.Fatal("failed save changed label", err)
	}
}

func TestPrivateMetadataProtocolAndRetention(t *testing.T) {
	for _, action := range []string{"consume", "expire", "delete"} {
		t.Run(action, func(t *testing.T) {
			s := testServer(t)
			id := readyPackage(t, s)
			patchLabel(t, s, id, nameEnvelope(17))
			w := request(s, "GET", "/api/packages/"+id, nil, false, "")
			var public map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil || w.Code != 200 || len(public) != 2 || public["status"] != "ready" || public["expiresAt"] == nil {
				t.Fatal("public response changed", w.Body, err)
			}
			switch action {
			case "consume":
				w = request(s, "POST", "/api/packages/"+id+"/consume", nil, false, "")
				if w.Code != 200 || w.Body.Len() != 72 || bytes.Contains(w.Body.Bytes(), []byte("encryptedName")) {
					t.Fatal("consume protocol changed")
				}
			case "expire":
				s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
				if err := s.sweep(); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if request(s, "DELETE", "/api/admin/packages/"+id, nil, true, "").Code != 204 {
					t.Fatal("delete failed")
				}
			}
			restarted, err := newServer(s.root, s.user, s.password, s.origin, s.quota)
			if err != nil {
				t.Fatal(err)
			}
			p := restarted.packages[id]
			if p.EncryptedName == nil || *p.EncryptedName != *nameEnvelope(17) {
				t.Fatal("historical name lost")
			}
			if action == "consume" && p.OpenedBrowser == nil {
				t.Fatal("historical profile lost")
			}
			w = request(restarted, "GET", "/api/admin/packages", nil, true, "")
			if !bytes.Contains(w.Body.Bytes(), []byte("encryptedName")) {
				t.Fatal("admin envelope missing")
			}
			patchLabel(t, restarted, id, nameEnvelope(32))
			restarted.now = func() time.Time { return p.ExpiresAt.Add(90*24*time.Hour + time.Second) }
			if err := restarted.sweep(); err != nil {
				t.Fatal(err)
			}
			if restarted.packages[id] != nil {
				t.Fatal("audit retention did not remove names/profile")
			}
			if _, err := os.Stat(restarted.dir(id)); !os.IsNotExist(err) {
				t.Fatal("metadata retained on disk")
			}
			if _, err := os.Stat(filepath.Join(restarted.root, "label-salt")); err != nil {
				t.Fatal("retention deleted salt", err)
			}
		})
	}
}
