package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testAuditKey(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	// The server never opens the wrapped key, so any well-formed bytes stand in for it here.
	body, _ := json.Marshal(AuditKey{Version: 1, PublicKey: encode(private.PublicKey().Bytes()), IV: encode(make([]byte, 12)), WrappedKey: encode(make([]byte, 154))})
	return private, body
}

// openSealed mirrors the browser's openRecord in web/audit.js.
func openSealed(t *testing.T, private *ecdh.PrivateKey, id string, r *SealedRecord) (Retrieval, int) {
	t.Helper()
	if !validSealedRecord(r) {
		t.Fatal("invalid sealed record", r)
	}
	decode := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }
	ephemeral, err := ecdh.P256().NewPublicKey(decode(r.EphemeralKey))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hkdf.Key(sha256.New, shared, decode(r.EphemeralKey), auditRecordInfo, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, err := gcm.Open(nil, decode(r.IV), decode(r.Ciphertext), []byte(auditRecordInfo+":"+id))
	if err != nil {
		t.Fatal("sealed record did not open", err)
	}
	var record Retrieval
	if err = json.Unmarshal(plaintext, &record); err != nil {
		t.Fatal(err)
	}
	return record, len(plaintext)
}

func enrollAudit(t *testing.T, s *Server) *ecdh.PrivateKey {
	t.Helper()
	private, body := testAuditKey(t)
	if w := request(s, "PUT", "/api/admin/audit-key", body, true, ""); w.Code != 204 {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	return private
}

func assertNoPlaintextAudit(t *testing.T, s *Server, id string) {
	t.Helper()
	for _, name := range []string{"meta.json", retrievalLogName} {
		b, err := os.ReadFile(filepath.Join(s.dir(id), name))
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"192.0.2.", "openedIp", "openedAt", "openedBrowser", "userAgent"} {
			if bytes.Contains(b, []byte(leak)) {
				t.Fatalf("%s still contains %q", name, leak)
			}
		}
	}
}

func TestAuditEnrollmentSealsMigratesAndStaysSealed(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := request(s, "GET", "/api/admin/config", nil, true, ""); !strings.Contains(w.Body.String(), `"auditKey":null`) {
		t.Fatal("unenrolled config must report a null audit key", w.Body)
	}
	if w := request(s, "PUT", "/api/admin/audit-key", []byte(`{}`), false, ""); w.Code != 401 {
		t.Fatal("unauthenticated enrollment", w.Code)
	}
	private := enrollAudit(t, s)
	assertNoPlaintextAudit(t, s, id)
	if p := s.packages[id]; p.auditPlain || !p.auditSealed || p.SealedRetrieval == nil || p.OpenedAt != nil {
		t.Fatal("migration incomplete", p)
	}
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	assertNoPlaintextAudit(t, s, id)
	page := auditPage(t, s, id, "")
	if len(page.Retrievals) != 2 || s.packages[id].RetrievalCount != 2 {
		t.Fatal("audit count", page)
	}
	for _, record := range page.Retrievals {
		if record.OpenedAt != nil || record.OpenedIP != "" {
			t.Fatal("plaintext record served", record)
		}
		opened, size := openSealed(t, private, id, record.SealedRecord)
		if opened.OpenedIP != "192.0.2.1" || opened.OpenedAt.IsZero() || opened.OpenedBrowser == nil || size%auditBlock != 0 {
			t.Fatal("sealed record content", opened, size)
		}
	}
	latest, _ := openSealed(t, private, id, s.packages[id].SealedRetrieval)
	if newest, _ := openSealed(t, private, id, page.Retrievals[1].SealedRecord); !latest.OpenedAt.Equal(newest.OpenedAt) || latest.OpenedIP != newest.OpenedIP {
		t.Fatal("latest retrieval", latest)
	}
	// A record bound to one package must not open as another's.
	other := *page.Retrievals[0].SealedRecord
	decode := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }
	ephemeral, _ := ecdh.P256().NewPublicKey(decode(other.EphemeralKey))
	shared, _ := private.ECDH(ephemeral)
	key, _ := hkdf.Key(sha256.New, shared, decode(other.EphemeralKey), auditRecordInfo, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, decode(other.IV), decode(other.Ciphertext), []byte(auditRecordInfo+":"+randomID())); err == nil {
		t.Fatal("record opened under another package ID")
	}

	_, second := testAuditKey(t)
	if w := request(s, "PUT", "/api/admin/audit-key", second, true, ""); w.Code != 409 {
		t.Fatal("audit key replaced", w.Code)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	if p := restarted.packages[id]; p.RetrievalCount != 2 || p.auditPlain || !p.auditSealed || restarted.auditKey == nil {
		t.Fatal("restart lost sealed audit state", p)
	}
	if err = os.Remove(filepath.Join(s.root, auditKeyName)); err != nil {
		t.Fatal(err)
	}
	if _, err = newServer(s.root, s.user, "", s.origin, s.quota); err == nil || !strings.Contains(err.Error(), "audit-key.json missing") {
		t.Fatal("missing audit key accepted", err)
	}
}

func TestAuditReenrollmentRequiresRemovingTheOldKey(t *testing.T) {
	s := testServer(t)
	id := reusablePackage(t, s)
	enrollAudit(t, s)
	if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if err := os.Remove(filepath.Join(s.root, "auth.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(s.root, s.user, testSetupToken, s.origin, s.quota); err == nil || !strings.Contains(err.Error(), "previous enrollment") {
		t.Fatal("stale audit key kept across re-enrollment", err)
	}
	if err := os.Remove(filepath.Join(s.root, auditKeyName)); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, s.user, testSetupToken, s.origin, s.quota)
	if err != nil || restarted.auditKey != nil {
		t.Fatal("re-enrollment blocked", err)
	}
	if w := request(restarted, "POST", "/api/admin/setup", setupBody(testSetupToken, testAuthentication), false, ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	enrollAudit(t, restarted)
	if w := directClaim(restarted, id, downloadClaimTokenFixture, nil); w.Code != 200 || restarted.packages[id].RetrievalCount != 2 {
		t.Fatal("claim after re-enrollment", w.Code)
	}
}

func TestAuditKeyValidation(t *testing.T) {
	s := testServer(t)
	_, valid := testAuditKey(t)
	var key AuditKey
	_ = json.Unmarshal(valid, &key)
	offCurve := append([]byte{4}, bytes.Repeat([]byte{1}, 64)...)
	for _, bad := range []AuditKey{
		{Version: 2, PublicKey: key.PublicKey, IV: key.IV, WrappedKey: key.WrappedKey},
		{Version: 1, PublicKey: base64.RawURLEncoding.EncodeToString(offCurve), IV: key.IV, WrappedKey: key.WrappedKey},
		{Version: 1, PublicKey: key.PublicKey[:20], IV: key.IV, WrappedKey: key.WrappedKey},
		{Version: 1, PublicKey: key.PublicKey, IV: "AAAA", WrappedKey: key.WrappedKey},
		{Version: 1, PublicKey: key.PublicKey, IV: key.IV, WrappedKey: "AAAA"},
	} {
		body, _ := json.Marshal(bad)
		if w := request(s, "PUT", "/api/admin/audit-key", body, true, ""); w.Code != 400 {
			t.Fatal("invalid audit key accepted", bad, w.Code)
		}
	}
	if w := request(s, "PUT", "/api/admin/audit-key", append(valid[:len(valid)-1], []byte(`,"extra":1}`)...), true, ""); w.Code != 400 {
		t.Fatal("unknown field accepted", w.Code)
	}
	if _, err := os.Stat(filepath.Join(s.root, auditKeyName)); !os.IsNotExist(err) {
		t.Fatal("rejected key was stored", err)
	}
}

func TestAuditMigrationSealsLegacyMetadataAndResumesAfterRestart(t *testing.T) {
	s := testServer(t)
	legacy := reusablePackage(t, s)
	if w := directClaim(s, legacy, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	// Packages from before the retrieval log keep their only record in metadata.
	if err := os.Remove(filepath.Join(s.dir(legacy), retrievalLogName)); err != nil {
		t.Fatal(err)
	}
	logged := reusablePackage(t, s)
	for i := 0; i < 2; i++ {
		if w := directClaim(s, logged, downloadClaimTokenFixture, nil); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	// A key published before the server restarts is applied by startup migration.
	private, body := testAuditKey(t)
	if err := os.WriteFile(filepath.Join(s.root, auditKeyName), body, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil {
		t.Fatal(err)
	}
	for id, count := range map[string]int{legacy: 1, logged: 2} {
		assertNoPlaintextAudit(t, restarted, id)
		page := auditPage(t, restarted, id, "")
		if len(page.Retrievals) != count || restarted.packages[id].RetrievalCount != int64(count) {
			t.Fatal("migrated count", id, page)
		}
		for _, record := range page.Retrievals {
			if opened, _ := openSealed(t, private, id, record.SealedRecord); opened.OpenedIP != "192.0.2.1" {
				t.Fatal("migrated content", opened)
			}
		}
		if entries, _ := os.ReadDir(restarted.dir(id)); len(entries) != 4 {
			t.Fatal("migration left staging files", entries)
		}
	}
}

func TestSealedRecordsArePaddedToBlocks(t *testing.T) {
	s := testServer(t)
	private := enrollAudit(t, s)
	id := randomID()
	short := Retrieval{OpenedIP: "192.0.2.1", OpenedBrowser: &BrowserProfile{UserAgent: "x"}}
	long := Retrieval{OpenedIP: "2001:db8::1", OpenedBrowser: &BrowserProfile{Browser: "unknown", OS: "unknown", DeviceType: "unknown", UserAgent: strings.Repeat("\" ", 128)}}
	var lengths []int
	for _, r := range []Retrieval{short, long} {
		sealed, err := s.seal(id, r)
		if err != nil {
			t.Fatal(err)
		}
		opened, size := openSealed(t, private, id, sealed)
		if opened.OpenedBrowser.UserAgent != r.OpenedBrowser.UserAgent || size%auditBlock != 0 {
			t.Fatal("padding", size)
		}
		lengths = append(lengths, len(sealed.Ciphertext))
	}
	if lengths[0] != base64.RawURLEncoding.EncodedLen(auditBlock+16) {
		t.Fatal("typical record exceeds one block", lengths)
	}
}
