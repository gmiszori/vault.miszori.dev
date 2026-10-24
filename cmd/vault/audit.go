package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const auditKeyName = "audit-key.json"
const auditRecordInfo = "vault.miszori.dev:audit-record:v1"

// Sealed plaintext is padded to whole blocks so ciphertext length does not reveal the
// User-Agent length; escaping at most doubles a 512-byte User-Agent, so 4 blocks suffice.
const auditBlock = 1024
const maxAuditPlaintext = 4 * auditBlock

// AuditKey is the administrator's retrieval-audit key pair. The server holds the public key
// and a copy of the private key wrapped by a password-derived key that never leaves the browser.
type AuditKey struct {
	Version    int    `json:"version"`
	PublicKey  string `json:"publicKey"`
	IV         string `json:"iv"`
	WrappedKey string `json:"wrappedKey"`
}

// SealedRecord is a retrieval encrypted to the audit public key under a fresh ephemeral
// P-256 key, so the server cannot read it back once written.
type SealedRecord struct {
	Version      int    `json:"version"`
	EphemeralKey string `json:"ephemeralKey"`
	IV           string `json:"iv"`
	Ciphertext   string `json:"ciphertext"`
}

// auditRecord is one stored retrieval. Plaintext fields appear only in records written
// before an audit key was enrolled and not yet sealed by migration.
type auditRecord struct {
	OpenedAt      *time.Time      `json:"openedAt,omitempty"`
	OpenedIP      string          `json:"openedIp,omitempty"`
	OpenedBrowser *BrowserProfile `json:"openedBrowser,omitempty"`
	*SealedRecord
}

func (r auditRecord) valid() bool {
	if r.SealedRecord != nil {
		return r.OpenedAt == nil && r.OpenedIP == "" && r.OpenedBrowser == nil && validSealedRecord(r.SealedRecord)
	}
	return r.OpenedAt != nil && !r.OpenedAt.IsZero()
}

func validSealedRecord(r *SealedRecord) bool {
	if r == nil || r.Version != 1 || !canonicalBase64(r.EphemeralKey, 65, 65) || !canonicalBase64(r.IV, 12, 12) || !canonicalBase64(r.Ciphertext, auditBlock+16, maxAuditPlaintext+16) {
		return false
	}
	ciphertext, _ := base64.RawURLEncoding.DecodeString(r.Ciphertext)
	return (len(ciphertext)-16)%auditBlock == 0
}

func validAuditKey(k AuditKey) (*ecdh.PublicKey, bool) {
	if k.Version != 1 || !canonicalBase64(k.PublicKey, 65, 65) || !canonicalBase64(k.IV, 12, 12) || !canonicalBase64(k.WrappedKey, 64, 512) {
		return nil, false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(k.PublicKey)
	public, err := ecdh.P256().NewPublicKey(raw)
	return public, err == nil
}

// initAuditKey runs before initAuth. A key without auth.json means a re-enrollment, whose new
// password could never unwrap it; a missing key beside an enrollment means a lost file.
func (s *Server) initAuditKey() error {
	_, err := os.Stat(filepath.Join(s.root, "auth.json"))
	enrolled := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, err := os.ReadFile(filepath.Join(s.root, auditKeyName))
	if errors.Is(err, os.ErrNotExist) {
		for _, p := range s.packages {
			if p.auditSealed && enrolled {
				return errors.New("audit-key.json missing while encrypted retrieval records exist; restore the original key file")
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	if !enrolled {
		return errors.New("audit-key.json belongs to a previous enrollment; remove it before re-enrolling (records sealed to it become unreadable)")
	}
	var key AuditKey
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 4096 || d.Decode(&key) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid audit-key.json")
	}
	public, ok := validAuditKey(key)
	if !ok {
		return errors.New("invalid audit-key.json")
	}
	s.auditKey, s.auditPublic = &key, public
	return nil
}

// seal encrypts a retrieval with ECDH(ephemeral, audit key) -> HKDF-SHA256 -> AES-256-GCM.
// The AAD binds the record to its package so records cannot be moved between packages.
func (s *Server) seal(id string, r Retrieval) (*SealedRecord, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(r); err != nil {
		return nil, err
	}
	// Trailing JSON whitespace keeps the padded plaintext parseable as-is.
	plaintext := append(buf.Bytes(), bytes.Repeat([]byte(" "), (auditBlock-buf.Len()%auditBlock)%auditBlock)...)
	if len(plaintext) > maxAuditPlaintext {
		return nil, errors.New("retrieval record too large")
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephemeral.ECDH(s.auditPublic)
	if err != nil {
		return nil, err
	}
	ephemeralKey := ephemeral.PublicKey().Bytes()
	key, err := hkdf.Key(sha256.New, shared, ephemeralKey, auditRecordInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	rand.Read(iv)
	ciphertext := gcm.Seal(nil, iv, plaintext, []byte(auditRecordInfo+":"+id))
	encode := base64.RawURLEncoding.EncodeToString
	return &SealedRecord{Version: 1, EphemeralKey: encode(ephemeralKey), IV: encode(iv), Ciphertext: encode(ciphertext)}, nil
}

// sealRecord seals a plaintext record once an audit key is enrolled; before that, records
// stay plaintext until the administrator's next sign-in enrolls a key and migrates them.
func (s *Server) sealRecord(id string, record auditRecord) (auditRecord, error) {
	if record.SealedRecord != nil || s.auditPublic == nil {
		return record, nil
	}
	sealed, err := s.seal(id, Retrieval{OpenedAt: *record.OpenedAt, OpenedIP: record.OpenedIP, OpenedBrowser: record.OpenedBrowser})
	return auditRecord{SealedRecord: sealed}, err
}

// setLastRetrieval keeps meta.json's copy of the latest retrieval in the same form as its log record.
func setLastRetrieval(p *Package, record auditRecord) {
	p.OpenedAt, p.OpenedIP, p.OpenedBrowser, p.SealedRetrieval = nil, "", nil, record.SealedRecord
	if record.SealedRecord == nil {
		at := *record.OpenedAt
		p.OpenedAt, p.OpenedIP, p.OpenedBrowser = &at, record.OpenedIP, record.OpenedBrowser
	}
}

// enrollAuditKey is called under s.mu. The key is set once: replacing it would strand
// every record already sealed to the previous key.
func (s *Server) enrollAuditKey(w http.ResponseWriter, r *http.Request) {
	var key AuditKey
	if !decode(w, r, &key) {
		return
	}
	public, ok := validAuditKey(key)
	if !ok {
		fail(w, 400, "Invalid audit key")
		return
	}
	if s.auditKey != nil {
		fail(w, 409, "Audit key already enrolled")
		return
	}
	b, err := json.Marshal(key)
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	err = s.publishNewFile(auditKeyName, b, func() { s.auditKey, s.auditPublic = &key, public })
	if errors.Is(err, os.ErrExist) {
		fail(w, 409, "Audit key already enrolled")
		return
	}
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	for _, p := range s.packages {
		if err = s.sealAudit(p); err != nil {
			s.auditSealFailed(p)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) auditSealFailed(p *Package) {
	if !p.auditSealLogged {
		p.auditSealLogged = true
		log.Print("ERROR: retrieval audit encryption failed; sweep will retry")
	}
}

// sealAudit replaces p's plaintext retrieval records with sealed ones. Called under s.mu.
// The sealed log is synced and renamed into place before metadata drops its plaintext copy,
// so an interrupted run leaves only plaintext that the next run seals.
func (s *Server) sealAudit(p *Package) error {
	if s.auditPublic == nil || !p.auditPlain || p.auditBroken {
		return nil
	}
	name := filepath.Join(s.dir(p.ID), retrievalLogName)
	var reader *bufio.Reader
	in, err := os.Open(name)
	if err == nil {
		defer in.Close()
		reader = bufio.NewReaderSize(in, maxRetrievalRecord)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, err := os.OpenFile(name+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(name + ".tmp")
	defer out.Close()
	writer := bufio.NewWriter(out)
	count := int64(0)
	write := func(record auditRecord) error {
		record, err := s.sealRecord(p.ID, record)
		if err != nil {
			return err
		}
		b, err := json.Marshal(record)
		if err != nil {
			return err
		}
		count++
		_, err = writer.Write(append(b, '\n'))
		return err
	}
	for reader != nil {
		record, _, err := readRetrieval(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err = write(record); err != nil {
			return err
		}
	}
	// Packages from before the retrieval log keep their only record in metadata.
	if count == 0 && p.OpenedAt != nil {
		if err = write(legacyRetrieval(p)); err != nil {
			return err
		}
	}
	if count != p.RetrievalCount {
		return errors.New("retrieval log changed during migration")
	}
	if count > 0 {
		if err = writer.Flush(); err == nil {
			err = out.Sync()
		}
		if err == nil {
			err = os.Rename(name+".tmp", name)
		}
		if err == nil {
			err = syncDir(s.dir(p.ID))
		}
		if err != nil {
			return err
		}
	}
	if p.OpenedAt != nil {
		last, err := s.sealRecord(p.ID, legacyRetrieval(p))
		if err != nil {
			return err
		}
		updated := *p
		setLastRetrieval(&updated, last)
		if err = s.save(&updated); err != nil {
			return err
		}
		setLastRetrieval(p, last)
	}
	p.auditPlain, p.auditSealed, p.auditSealLogged = false, count > 0, false
	return nil
}

func syncDir(name string) error {
	d, err := os.Open(name)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}
