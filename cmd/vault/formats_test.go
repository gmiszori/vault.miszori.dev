package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func createFormattedPackage(t *testing.T, s *Server, format string, oneTime bool) (string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ttlSeconds": 3600, "format": format, "oneTime": oneTime})
	w := request(s, "POST", "/api/admin/packages", body, true, "")
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body)
	}
	var created struct {
		ID, UploadToken, Format string
		OneTime                 bool
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Format != format || created.OneTime != oneTime {
		t.Fatal("create omitted format/access mode", w.Body)
	}
	return created.ID, created.UploadToken
}

func uploadFormatRecord(s *Server, id, token string, index int, data []byte) *httptest.ResponseRecorder {
	return request(s, "PUT", "/api/admin/packages/"+id+"/chunks/"+strconv.Itoa(index), data, true, token)
}

func encryptTextRecord(t *testing.T, index byte, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	nonce[len(nonce)-1] = index
	return aead.Seal(nil, nonce, plaintext, nil)
}

func readyTextPackage(t *testing.T, s *Server, oneTime bool) (string, []byte) {
	t.Helper()
	id, token := createFormattedPackage(t, s, "text", oneTime)
	records := [][]byte{
		encryptTextRecord(t, 0, []byte(`{"version":1,"format":"text"}`)),
		encryptTextRecord(t, 1, []byte("Private UTF-8 text: árvíztűrő tükörfúrógép 🌍")),
	}
	var framed bytes.Buffer
	for n, record := range records {
		if w := uploadFormatRecord(s, id, token, n, record); w.Code != 204 {
			t.Fatal(w.Code, w.Body)
		}
		if err := binary.Write(&framed, binary.BigEndian, uint32(len(record))); err != nil {
			t.Fatal(err)
		}
		framed.Write(record)
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(2), true, token); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	return id, framed.Bytes()
}

func TestCreatePackageFormatValidation(t *testing.T) {
	s := testServer(t)
	for _, value := range []string{`null`, `""`, `"Text"`, `"FILES"`, `"text "`, `"binary"`, `true`, `1`, `[]`, `{}`} {
		body := []byte(`{"ttlSeconds":3600,"format":` + value + `}`)
		if w := request(s, "POST", "/api/admin/packages", body, true, ""); w.Code != 400 {
			t.Fatal("invalid format accepted", value, w.Code)
		}
	}
	if len(s.packages) != 0 {
		t.Fatal("invalid formats allocated packages")
	}
	w := request(s, "POST", "/api/admin/packages", []byte(`{"ttlSeconds":3600}`), true, "")
	if w.Code != 201 || !bytes.Contains(w.Body.Bytes(), []byte(`"format":"files"`)) {
		t.Fatal("default format missing", w.Code, w.Body)
	}
	for _, format := range []string{"files", "text"} {
		id, _ := createFormattedPackage(t, s, format, true)
		if s.packages[id].Format != format {
			t.Fatal("incorrect package format")
		}
	}
}

func TestTextPackageProofFramingAuditAndAccessModes(t *testing.T) {
	for _, oneTime := range []bool{true, false} {
		t.Run(strconv.FormatBool(oneTime), func(t *testing.T) {
			s := testServer(t)
			id, framed := readyTextPackage(t, s, oneTime)
			public := request(s, "GET", "/api/packages/"+id, nil, false, "")
			var metadata map[string]any
			if err := json.Unmarshal(public.Body.Bytes(), &metadata); err != nil || public.Code != 200 || len(metadata) != 4 || metadata["format"] != "text" || metadata["oneTime"] != oneTime {
				t.Fatal("public format schema", public.Body, err)
			}
			if len(auditPage(t, s, id, "").Retrievals) != 0 {
				t.Fatal("metadata GET started a retrieval")
			}
			for _, token := range []string{"", "invalid", downloadClaimHashFixture} {
				if w := directClaim(s, id, token, nil); w.Code != 404 {
					t.Fatal("unprotected text retrieval", w.Code)
				}
			}
			if s.packages[id].RetrievalCount != 0 {
				t.Fatal("invalid proofs altered audit")
			}
			disk, err := os.ReadFile(filepath.Join(s.dir(id), "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			admin := request(s, "GET", "/api/admin/packages", nil, true, "")
			if !bytes.Contains(admin.Body.Bytes(), []byte(`"format":"text"`)) {
				t.Fatal("admin format missing")
			}
			for _, body := range [][]byte{public.Body.Bytes(), admin.Body.Bytes(), disk, framed} {
				if bytes.Contains(body, []byte("Private UTF-8 text")) || bytes.Contains(body, []byte(`"version":1`)) {
					t.Fatal("plaintext leaked")
				}
			}
			restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
			if err != nil || restarted.packages[id].Format != "text" || restarted.packages[id].OneTime != oneTime {
				t.Fatal("text metadata lost on restart", err)
			}
			s = restarted
			reads := 1
			if !oneTime {
				reads = 3
			}
			for n := 0; n < reads; n++ {
				if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), framed) {
					t.Fatal("text framing changed", w.Code)
				}
			}
			if oneTime {
				if w := directClaim(s, id, downloadClaimTokenFixture, nil); w.Code != 404 {
					t.Fatal("one-time text repeated")
				}
			} else {
				first, firstDone := startPausedRetrieval(t, s, id)
				second, secondDone := startPausedRetrieval(t, s, id)
				close(first.release)
				close(second.release)
				<-firstDone
				<-secondDone
				if !bytes.Equal(first.Body.Bytes(), framed) || !bytes.Equal(second.Body.Bytes(), framed) {
					t.Fatal("parallel reusable text failed")
				}
				reads += 2
			}
			page := auditPage(t, s, id, "")
			if len(page.Retrievals) != reads || s.packages[id].RetrievalCount != int64(reads) {
				t.Fatal("text retrieval audit incomplete")
			}
			for _, record := range page.Retrievals {
				if record.OpenedAt.IsZero() || record.OpenedIP == "" || record.OpenedBrowser == nil {
					t.Fatal("text retrieval missing time/IP/browser")
				}
			}
			restarted, err = newServer(s.root, s.user, "", s.origin, s.quota)
			if err != nil || restarted.packages[id].RetrievalCount != int64(reads) || restarted.packages[id].Format != "text" {
				t.Fatal("text audit/format lost on restart", err)
			}
		})
	}
}

func TestTextUploadRecordSizeLimitsAndRetry(t *testing.T) {
	for _, tc := range []struct {
		name          string
		record, size  int
		unknownLength bool
	}{
		{"manifest-too-short", 0, 15, false},
		{"manifest-too-large-known", 0, maxTextManifestCiphertext + 1, false},
		{"manifest-too-large-streamed", 0, maxTextManifestCiphertext + 1, true},
		{"text-empty", 1, 16, false},
		{"text-too-large-known", 1, maxChunk + 1, false},
		{"text-too-large-streamed", 1, maxChunk + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			id, token := createFormattedPackage(t, s, "text", true)
			if tc.record == 1 {
				if w := uploadFormatRecord(s, id, token, 0, make([]byte, maxTextManifestCiphertext)); w.Code != 204 {
					t.Fatal(w.Code)
				}
			}
			before := s.packages[id].Bytes
			r := httptest.NewRequest(http.MethodPut, "/api/admin/packages/"+id+"/chunks/"+strconv.Itoa(tc.record), bytes.NewReader(make([]byte, tc.size)))
			r.SetBasicAuth("admin", testAuthentication)
			r.Header.Set("X-Upload-Token", token)
			if tc.unknownLength {
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 413 {
				t.Fatal("invalid text size accepted", w.Code)
			}
			if p := s.packages[id]; p.Chunks != tc.record || p.Bytes != before {
				t.Fatal("rejected upload changed accounting")
			}
			for _, path := range []string{s.chunk(id, tc.record), s.chunk(id, tc.record) + ".tmp"} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("rejected upload left ciphertext/tmp", path, err)
				}
			}
			min, _ := textRecordLimits(tc.record)
			if w := uploadFormatRecord(s, id, token, tc.record, make([]byte, int(min))); w.Code != 204 {
				t.Fatal("same-index retry failed", w.Code)
			}
		})
	}
}

func TestTextUploadMaximumAndExactRecordCount(t *testing.T) {
	s := testServer(t)
	id, token := createFormattedPackage(t, s, "text", false)
	for n, size := range []int{maxTextManifestCiphertext, maxChunk} {
		if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(n), true, token); w.Code != 400 {
			t.Fatal("incomplete text finalized", n, w.Code)
		}
		if w := uploadFormatRecord(s, id, token, n, bytes.Repeat([]byte{0xff}, size)); w.Code != 204 {
			t.Fatal("maximum-size opaque ciphertext rejected", n, w.Code, w.Body)
		}
	}
	if s.packages[id].Bytes != maxTextPackageBytes {
		t.Fatal("incorrect maximum text size")
	}
	if w := uploadFormatRecord(s, id, token, 2, make([]byte, 16)); w.Code != 400 {
		t.Fatal("third text record accepted", w.Code)
	}
	if _, err := os.Stat(s.chunk(id, 2) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("third record created tmp", err)
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(3), true, token); w.Code != 400 {
		t.Fatal("wrong text count finalized", w.Code)
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(2), true, token); w.Code != 204 {
		t.Fatal("maximum text did not finalize", w.Code, w.Body)
	}
}

func TestTextFinalizeValidatesStoredRecordSizes(t *testing.T) {
	for _, tc := range []struct{ record, size int }{{0, 15}, {0, maxTextManifestCiphertext + 1}, {1, 16}, {1, maxChunk + 1}} {
		t.Run(fmt.Sprintf("%d-%d", tc.record, tc.size), func(t *testing.T) {
			s := testServer(t)
			id, token := createFormattedPackage(t, s, "text", true)
			for n := 0; n < 2; n++ {
				if w := uploadFormatRecord(s, id, token, n, make([]byte, 32)); w.Code != 204 {
					t.Fatal(w.Code)
				}
			}
			if err := os.Truncate(s.chunk(id, tc.record), int64(tc.size)); err != nil {
				t.Fatal(err)
			}
			s.packages[id].Bytes = int64(32 + tc.size)
			if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(2), true, token); w.Code != 400 || s.packages[id].Status != "uploading" {
				t.Fatal("invalid stored text finalized", w.Code)
			}
		})
	}
}

func TestFileFormatLegacyAndExistingLimits(t *testing.T) {
	s := testServer(t)
	id, token := createFormattedPackage(t, s, "files", true)
	for n, size := range []int{maxTextManifestCiphertext + 1, 16, 32} {
		if w := uploadFormatRecord(s, id, token, n, make([]byte, size)); w.Code != 204 {
			t.Fatal("text limits applied to files", w.Code)
		}
	}
	if w := request(s, "POST", "/api/admin/packages/"+id+"/finalize", finalizeBody(3), true, token); w.Code != 204 {
		t.Fatal("file count restricted", w.Code)
	}
	path := filepath.Join(s.dir(id), "meta.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "format")
	delete(legacy, "oneTime")
	data, _ = json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := newServer(s.root, s.user, "", s.origin, s.quota)
	if err != nil || restarted.packages[id].Format != "files" || !restarted.packages[id].OneTime {
		t.Fatal("legacy format/default changed", err)
	}
	meta := request(restarted, "GET", "/api/packages/"+id, nil, false, "")
	if !bytes.Contains(meta.Body.Bytes(), []byte(`"format":"files"`)) {
		t.Fatal("legacy public format missing")
	}
	if w := directClaim(restarted, id, downloadClaimTokenFixture, nil); w.Code != 200 {
		t.Fatal("legacy proof failed", w.Code)
	}
	id, token = createFormattedPackage(t, s, "files", true)
	s.quota = maxPackageBytes + 1024*1024
	s.packages[id].Bytes = maxPackageBytes - 16
	if w := uploadFormatRecord(s, id, token, 0, make([]byte, 16)); w.Code != 204 {
		t.Fatal("existing 20 GiB file allowance reduced", w.Code, w.Body)
	}
	if w := uploadFormatRecord(s, id, token, 1, make([]byte, 16)); w.Code != 413 {
		t.Fatal("existing file package limit removed", w.Code)
	}
}
