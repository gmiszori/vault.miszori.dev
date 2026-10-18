package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type authRecord struct {
	Version  int    `json:"version"`
	Username string `json:"username"`
	Verifier string `json:"verifier"`
}

func (s *Server) initAuth(setupToken string) error {
	name := filepath.Join(s.root, "auth.json")
	f, err := os.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		if len([]rune(setupToken)) < 32 {
			return errors.New("ADMIN_SETUP_TOKEN must be at least 32 characters on first setup")
		}
		s.setupVerifier = sha256.Sum256([]byte(setupToken))
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return err
	}
	var record authRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > 4096 || d.Decode(&record) != nil || d.Decode(&struct{}{}) != io.EOF || record.Version != 1 || record.Username == "" || strings.ContainsAny(record.Username, ":\r\n") || !validID(record.Verifier) {
		return errors.New("invalid auth.json")
	}
	if err := f.Chmod(0600); err != nil {
		return err
	}
	s.auth = &record
	s.user = record.Username
	return nil
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return (origin == "" || origin == "http://"+r.Host || origin == "https://"+r.Host) && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (s *Server) authThrottled(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.limits["auth:"+peerIP(r)]
	return s.now().Sub(b.start) < time.Minute && b.count >= 20
}

func (s *Server) authFailure(w http.ResponseWriter, r *http.Request, code int, message string) {
	if !s.gate.allowAuthFailure(s.now()) || !s.allowed("auth:"+peerIP(r), 20) {
		fail(w, 429, "Too many attempts")
		return
	}
	fail(w, code, message)
}

func (s *Server) authenticated(r *http.Request) bool {
	u, secret, ok := r.BasicAuth()
	if !ok || !canonicalBase64(secret, 32, 32) {
		return false
	}
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(secret)
	verifier := sha256.Sum256(decoded)
	userHash := sha256.Sum256([]byte(u))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auth == nil {
		return false
	}
	wantUser := sha256.Sum256([]byte(s.auth.Username))
	wantVerifier, _ := hex.DecodeString(s.auth.Verifier)
	return subtle.ConstantTimeCompare(userHash[:], wantUser[:])&subtle.ConstantTimeCompare(verifier[:], wantVerifier) == 1
}

// publishAuth never replaces an existing enrollment, even across server processes.
// The file and directory are synced before reporting successful setup.
func (s *Server) publishAuth(record authRecord) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.root, ".auth-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), filepath.Join(s.root, "auth.json")); err != nil {
		return err
	}
	// A published enrollment must not be retried if a later durability step fails.
	s.auth = &record
	s.setupVerifier = [32]byte{}
	if err = os.Remove(f.Name()); err != nil {
		return err
	}
	d, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.auth != nil {
		s.mu.Unlock()
		fail(w, 409, "Already initialized")
		return
	}
	s.mu.Unlock()
	var req struct {
		SetupToken     string `json:"setupToken"`
		Authentication string `json:"authentication"`
	}
	if !decode(w, r, &req) {
		s.gate.allowAuthFailure(s.now())
		s.allowed("auth:"+peerIP(r), 20)
		return
	}
	if req.SetupToken == "" || !canonicalBase64(req.Authentication, 32, 32) {
		s.authFailure(w, r, 400, "Invalid request")
		return
	}
	tokenHash := sha256.Sum256([]byte(req.SetupToken))
	s.mu.Lock()
	if s.auth != nil {
		s.mu.Unlock()
		fail(w, 409, "Already initialized")
		return
	}
	if subtle.ConstantTimeCompare(tokenHash[:], s.setupVerifier[:]) != 1 {
		s.mu.Unlock()
		s.authFailure(w, r, 401, "Authentication required")
		return
	}
	if s.user == "" || strings.ContainsAny(s.user, ":\r\n") {
		s.mu.Unlock()
		fail(w, 500, "Invalid administrator username")
		return
	}
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(req.Authentication)
	verifier := sha256.Sum256(decoded)
	err := s.publishAuth(authRecord{Version: 1, Username: s.user, Verifier: hex.EncodeToString(verifier[:])})
	s.mu.Unlock()
	if errors.Is(err, os.ErrExist) {
		fail(w, 409, "Already initialized")
		return
	}
	if err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
