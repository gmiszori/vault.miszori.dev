package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxChunk = 8*1024*1024 + 16
const maxChunks = 30000
const maxPackageBytes int64 = 20*1024*1024*1024 + maxChunks*16 + 8*1024*1024
const maxClaimsPerPackagePerMinute = 30

type Package struct {
	ID             string          `json:"id"`
	OneTime        bool            `json:"oneTime"`
	Format         string          `json:"format"`
	RetrievalCount int64           `json:"retrievalCount"`
	Status         string          `json:"status"`
	CreatedAt      time.Time       `json:"createdAt"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	OpenedAt       *time.Time      `json:"openedAt,omitempty"`
	OpenedIP       string          `json:"openedIp,omitempty"`
	Chunks         int             `json:"chunks"`
	Bytes          int64           `json:"bytes"`
	TokenHash      string          `json:"-"`
	ClaimHash      string          `json:"claimHash,omitempty"`
	EncryptedName  *EncryptedName  `json:"encryptedName,omitempty"`
	OpenedBrowser  *BrowserProfile `json:"openedBrowser,omitempty"`
	// SealedRetrieval replaces the plaintext Opened* fields once an audit key is enrolled.
	SealedRetrieval *SealedRecord `json:"sealedRetrieval,omitempty"`
	activeReads     int
	auditBroken     bool
	auditPlain      bool
	auditSealed     bool
	auditSealLogged bool
	cleanupPending  bool
	chunkInFlight   bool
}
type diskPackage struct {
	Package
	TokenHash string `json:"tokenHash"`
}
type bucket struct {
	start time.Time
	count int
}
type Server struct {
	mu                 sync.Mutex
	root, user, origin string
	auth               *authRecord
	setupVerifier      [32]byte
	packages           map[string]*Package
	limits             map[string]bucket
	quota              int64
	reservedBytes      int64
	now                func() time.Time
	labelKey           LabelKey
	auditKey           *AuditKey
	auditPublic        *ecdh.PublicKey
	gate               *requestGate
	trustedProxy       *net.IPNet
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func (s *Server) dir(id string) string { return filepath.Join(s.root, id) }
func (s *Server) chunk(id string, n int) string {
	return filepath.Join(s.dir(id), fmt.Sprintf("%06d.bin", n))
}
func (s *Server) save(p *Package) error {
	b, err := json.Marshal(diskPackage{*p, p.TokenHash})
	if err != nil {
		return err
	}
	name := filepath.Join(s.dir(p.ID), "meta.json")
	f, err := os.OpenFile(name+".tmp", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
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
	if err = os.Rename(name+".tmp", name); err != nil {
		return err
	}
	d, err := os.Open(s.dir(p.ID))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *Server) purge(p *Package, status string) error {
	// Keep failed/deferred cleanup retryable and quota-held until every ciphertext record is removed.
	p.cleanupPending = true
	// Make revocation durable before cleanup; reusable streams already admitted may finish.
	p.Status = status
	p.TokenHash = ""
	if err := s.save(p); err != nil {
		return err
	}
	if p.activeReads > 0 {
		return nil
	}
	entries, err := os.ReadDir(s.dir(p.ID))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() != "meta.json" && e.Name() != retrievalLogName {
			if err = os.RemoveAll(filepath.Join(s.dir(p.ID), e.Name())); err != nil {
				return err
			}
		}
	}
	p.cleanupPending = false
	return nil
}
func newServer(root, user, setupToken, origin string, quota int64) (*Server, error) {
	if user == "" {
		user = "admin"
	}
	_, trustedProxy, _ := net.ParseCIDR(defaultTrustedProxyCIDR)
	s := &Server{root: root, user: user, origin: origin, quota: quota, packages: map[string]*Package{}, limits: map[string]bucket{}, now: time.Now, gate: newRequestGate(defaultGateLimits()), trustedProxy: trustedProxy}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "meta.json"))
		if errors.Is(err, os.ErrNotExist) {
			if err = os.RemoveAll(filepath.Join(root, e.Name())); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		d := diskPackage{Package: Package{OneTime: true, Format: "files"}}
		if err = json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		if d.ID != e.Name() {
			return nil, errors.New("invalid stored package ID")
		}
		if d.Format != "files" && d.Format != "text" {
			return nil, errors.New("invalid stored package format")
		}
		p := d.Package
		p.TokenHash = d.TokenHash
		if err = s.restoreRetrievalCount(&p); err != nil {
			return nil, err
		}
		s.packages[p.ID] = &p
	}
	if err = s.initLabelKey(); err != nil {
		return nil, err
	}
	if err = s.initAuditKey(); err != nil {
		return nil, err
	}
	if err = s.initAuth(setupToken); err != nil {
		return nil, err
	}
	for _, p := range s.packages {
		status := p.Status
		if status == "consuming" || status == "uploading" {
			status = "failed"
		}
		if status != "ready" {
			if err = s.purge(p, status); err != nil {
				return nil, err
			}
		}
	}
	if err = s.sweep(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *Server) sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, p := range s.packages {
		if err := s.sealAudit(p); err != nil {
			s.auditSealFailed(p)
		}
		if (p.Status == "uploading" || p.Status == "ready") && !now.Before(p.ExpiresAt) {
			if err := s.purge(p, "expired"); err != nil {
				return err
			}
		}
		if p.activeReads == 0 && p.Status != "ready" && p.Status != "uploading" && p.Status != "consuming" && p.cleanupPending {
			if err := s.purge(p, p.Status); err != nil {
				return err
			}
		}
		if p.activeReads == 0 && p.Status != "ready" && p.Status != "uploading" && p.Status != "consuming" && now.Sub(p.ExpiresAt) > 90*24*time.Hour {
			if err := os.RemoveAll(s.dir(id)); err != nil {
				return err
			}
			delete(s.packages, id)
		}
	}
	return nil
}
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "Invalid request")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "Invalid request")
		return false
	}
	return true
}
func (s *Server) allowed(key string, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allowedLocked(key, n)
}
func (s *Server) allowedLocked(key string, n int) bool {
	now := s.now()
	b, tracked := s.limits[key]
	if now.Sub(b.start) >= time.Minute {
		b = bucket{start: now}
	}
	b.count++
	// A full table refuses only new keys; already-tracked clients keep their own budgets.
	if !tracked && len(s.limits) >= 10000 {
		for k, v := range s.limits {
			if now.Sub(v.start) >= time.Minute {
				delete(s.limits, k)
			}
		}
		if len(s.limits) >= 10000 {
			return false
		}
	}
	s.limits[key] = b
	return b.count <= n
}

// Valid package IDs and claim proofs are unguessable, so only failed public requests
// spend the shared budget; exhausting it cannot block recipients holding real links.
func (s *Server) publicFailure(w http.ResponseWriter, code int, msg string) {
	if !s.gate.allowPublicFailure(s.now()) {
		fail(w, 429, "Too many requests")
		return
	}
	fail(w, code, msg)
}
func guardRequestBody(w http.ResponseWriter, r *http.Request) func() {
	if r.ContentLength == 0 && len(r.TransferEncoding) == 0 {
		return func() {}
	}
	// Error responses must not leave an unread body draining on an unbounded keep-alive socket.
	r.Close = true
	w.Header().Set("Connection", "close")
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Minute))
	// net/http closes (and may drain) the original body after the handler returns.
	return func() { _ = controller.SetReadDeadline(time.Now()) }
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer guardRequestBody(w, r)()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}
	release, admitted := s.gate.acquire(r)
	if !admitted {
		w.Header().Set("Retry-After", "5")
		fail(w, 429, "Server busy; no package has been claimed")
		return
	}
	defer release()
	admin := strings.HasPrefix(r.URL.Path, "/api/admin/")
	if admin {
		if !sameOrigin(r) {
			s.authFailure(w, r, 403, "Cross-origin request denied")
			return
		}
		if r.URL.Path == "/api/admin/auth" && r.Method == http.MethodGet {
			if !s.allowed("discovery:"+s.peerIP(r), 20) || !s.gate.allowAdminDiscovery(s.now()) {
				fail(w, 429, "Too many requests")
				return
			}
			s.mu.Lock()
			writeJSON(w, 200, map[string]any{"initialized": s.auth != nil, "username": s.user, "labelKey": s.labelKey, "publicOrigin": s.origin})
			s.mu.Unlock()
			return
		}
		if s.authThrottled(r) {
			fail(w, 429, "Too many attempts")
			return
		}
		if r.URL.Path == "/api/admin/setup" && r.Method == http.MethodPost {
			if !s.gate.allowAdminDiscovery(s.now()) {
				fail(w, 429, "Too many requests")
				return
			}
			s.setup(w, r)
			return
		}
		if !s.authenticated(r) {
			s.authFailure(w, r, 401, "Authentication required")
			return
		}
		s.admin(w, r)
		return
	}
	if !s.allowed("public:"+s.peerIP(r), 120) {
		fail(w, 429, "Too many requests")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "packages" || !validID(parts[2]) {
		s.publicFailure(w, 404, "Package already viewed or does not exist")
		return
	}
	id := parts[2]
	if len(parts) == 4 && parts[3] == "consume" && r.Method == "POST" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			r.Close = true
			w.Header().Set("Connection", "close")
			s.publicFailure(w, 400, "Download claims must not contain a request body")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			s.publicFailure(w, 403, "Cross-origin request denied")
			return
		}
		s.consume(w, r, id)
		return
	}
	if len(parts) == 3 && r.Method == "GET" {
		s.mu.Lock()
		p := s.packages[id]
		if p == nil || p.Status != "ready" || !validClaimHash(p.ClaimHash) || !s.now().Before(p.ExpiresAt) {
			s.mu.Unlock()
			s.publicFailure(w, 404, "Package already viewed or does not exist")
			return
		}
		defer s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"status": "ready", "expiresAt": p.ExpiresAt, "oneTime": p.OneTime, "format": p.Format})
		return
	}
	s.publicFailure(w, 404, "Not found")
}
func (s *Server) storageUsedLocked() int64 {
	var used int64
	for _, p := range s.packages {
		if p.Status == "ready" || p.Status == "uploading" || p.Status == "consuming" || p.activeReads > 0 || p.cleanupPending {
			used += p.Bytes
		}
	}
	return used + s.reservedBytes
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	if path == "config" && r.Method == "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"publicOrigin": s.origin, "labelKey": s.labelKey, "auditKey": s.auditKey})
		return
	}
	if parts := strings.Split(path, "/"); r.Method == http.MethodPut && len(parts) == 4 && parts[0] == "packages" && validID(parts[1]) && parts[2] == "chunks" {
		s.uploadChunk(w, r, parts[1], parts[3])
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == "audit-key" && r.Method == http.MethodPut {
		s.enrollAuditKey(w, r)
		return
	}
	if path == "packages" && r.Method == "GET" {
		ps := make([]Package, 0, len(s.packages))
		for _, p := range s.packages {
			ps = append(ps, *p)
		}
		writeJSON(w, 200, map[string]any{
			"packages": ps,
			"storage":  map[string]int64{"usedBytes": s.storageUsedLocked(), "maxBytes": s.quota},
		})
		return
	}
	if path == "packages" && r.Method == "POST" {
		var req struct {
			TTL     int64           `json:"ttlSeconds"`
			OneTime *bool           `json:"oneTime"`
			Format  json.RawMessage `json:"format"`
		}
		if !decode(w, r, &req) {
			return
		}
		format := "files"
		if req.Format != nil {
			var value string
			if err := json.Unmarshal(req.Format, &value); err != nil || (value != "files" && value != "text") {
				fail(w, 400, "Format must be files or text")
				return
			}
			format = value
		}
		if req.TTL < 60 || req.TTL > 30*86400 {
			fail(w, 400, "Expiry must be between 60 seconds and 30 days")
			return
		}
		active := 0
		for _, p := range s.packages {
			if p.Status == "uploading" || p.Status == "ready" || p.Status == "consuming" {
				active++
			}
		}
		if active >= 100 {
			fail(w, 429, "Too many active packages")
			return
		}
		now := s.now()
		token := randomID()
		oneTime := req.OneTime == nil || *req.OneTime
		p := &Package{ID: randomID(), OneTime: oneTime, Format: format, Status: "uploading", CreatedAt: now, ExpiresAt: now.Add(time.Duration(req.TTL) * time.Second), TokenHash: hash(token)}
		if err := os.Mkdir(s.dir(p.ID), 0700); err != nil {
			fail(w, 500, "Storage unavailable")
			return
		}
		if err := s.save(p); err != nil {
			_ = os.RemoveAll(s.dir(p.ID))
			fail(w, 500, "Storage unavailable")
			return
		}
		s.packages[p.ID] = p
		writeJSON(w, 201, map[string]any{"id": p.ID, "uploadToken": token, "expiresAt": p.ExpiresAt, "oneTime": p.OneTime, "format": p.Format})
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "packages" || !validID(parts[1]) {
		fail(w, 404, "Not found")
		return
	}
	p := s.packages[parts[1]]
	if p == nil {
		fail(w, 404, "Not found")
		return
	}
	if len(parts) == 3 && parts[2] == "retrievals" && r.Method == "GET" {
		s.retrievals(w, r, p)
		return
	}
	if len(parts) == 2 && r.Method == "PATCH" {
		s.patchName(w, r, p)
		return
	}
	if len(parts) == 2 && r.Method == "DELETE" {
		if p.Status == "consuming" {
			fail(w, 409, "Download in progress")
			return
		}
		if err := s.purge(p, "deleted"); err != nil {
			fail(w, 500, "Deletion failed")
			return
		}
		w.WriteHeader(204)
		return
	}
	if p.Status != "uploading" || !s.now().Before(p.ExpiresAt) {
		fail(w, 409, "Package not uploading")
		return
	}
	token := hash(r.Header.Get("X-Upload-Token"))
	if subtle.ConstantTimeCompare([]byte(token), []byte(p.TokenHash)) != 1 {
		fail(w, 403, "Invalid upload token")
		return
	}
	if len(parts) == 3 && parts[2] == "finalize" && r.Method == "POST" {
		var req struct {
			Chunks    int    `json:"chunks"`
			ClaimHash string `json:"claimHash"`
		}
		if !decode(w, r, &req) {
			return
		}
		if p.chunkInFlight {
			fail(w, 409, "A chunk upload is still in progress")
			return
		}
		if req.Chunks != p.Chunks || req.Chunks < 1 || !validClaimHash(req.ClaimHash) {
			fail(w, 400, "Incomplete package")
			return
		}
		if p.Format == "text" {
			valid, err := s.validTextRecords(p)
			if err != nil {
				fail(w, 500, "Storage unavailable")
				return
			}
			if !valid {
				fail(w, 400, "Text packages require two records within text size limits")
				return
			}
		}
		p.Status = "ready"
		p.ClaimHash = req.ClaimHash
		p.TokenHash = ""
		if err := s.save(p); err != nil {
			p.Status = "failed"
			_ = s.purge(p, "failed")
			fail(w, 500, "Storage unavailable")
			return
		}
		w.WriteHeader(204)
		return
	}
	fail(w, 404, "Not found")
}

// uploadChunk reserves quota under s.mu, streams the body to disk without the lock so
// recipients and cleanup are never blocked by a slow upload, then commits under s.mu.
func (s *Server) uploadChunk(w http.ResponseWriter, r *http.Request, id, index string) {
	s.mu.Lock()
	p := s.packages[id]
	if p == nil {
		s.mu.Unlock()
		fail(w, 404, "Not found")
		return
	}
	if p.Status != "uploading" || !s.now().Before(p.ExpiresAt) {
		s.mu.Unlock()
		fail(w, 409, "Package not uploading")
		return
	}
	token := hash(r.Header.Get("X-Upload-Token"))
	if subtle.ConstantTimeCompare([]byte(token), []byte(p.TokenHash)) != 1 {
		s.mu.Unlock()
		fail(w, 403, "Invalid upload token")
		return
	}
	n, err := strconv.Atoi(index)
	if err != nil || n < 0 || n >= maxChunks {
		s.mu.Unlock()
		fail(w, 400, "Invalid chunk index")
		return
	}
	// One record at a time per package preserves strict ordering without holding s.mu.
	if p.chunkInFlight {
		s.mu.Unlock()
		fail(w, 409, "A chunk upload is already in progress")
		return
	}
	if n != p.Chunks {
		s.mu.Unlock()
		fail(w, 409, "Chunks must be uploaded in order; retries must reuse the next index")
		return
	}
	minBytes, limit, packageLimit := int64(16), int64(maxChunk), maxPackageBytes
	if p.Format == "text" {
		if n >= 2 {
			s.mu.Unlock()
			fail(w, 400, "Text packages require exactly two records")
			return
		}
		minBytes, limit = textRecordLimits(n)
		packageLimit = maxTextPackageBytes
	}
	if remaining := packageLimit - p.Bytes; remaining < limit {
		limit = remaining
	}
	if limit < minBytes || r.ContentLength > limit {
		s.mu.Unlock()
		fail(w, 413, "Chunk, package, or storage limit exceeded")
		return
	}
	// Reserve the declared length, or the record maximum when the length is unknown.
	if r.ContentLength >= 0 {
		limit = r.ContentLength
	}
	if limit < minBytes || s.storageUsedLocked()+limit > s.quota {
		s.mu.Unlock()
		fail(w, 413, "Chunk, package, or storage limit exceeded")
		return
	}
	p.chunkInFlight = true
	s.reservedBytes += limit
	s.mu.Unlock()

	tmp := s.chunk(id, n) + ".tmp"
	var count int64
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	opened := err == nil
	if opened {
		count, err = io.Copy(f, http.MaxBytesReader(w, r.Body, limit))
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.reservedBytes -= limit
	p.chunkInFlight = false
	if !opened {
		fail(w, 500, "Storage unavailable")
		return
	}
	// Deletion or expiry may have purged the package while the body was being written.
	if p.Status != "uploading" || !s.now().Before(p.ExpiresAt) {
		_ = os.Remove(tmp)
		fail(w, 409, "Package not uploading")
		return
	}
	if err != nil || count < minBytes || p.Bytes+count > packageLimit || s.storageUsedLocked()+count > s.quota {
		_ = os.Remove(tmp)
		fail(w, 413, "Chunk, package, or storage limit exceeded")
		return
	}
	if err = os.Rename(tmp, s.chunk(id, n)); err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	p.Chunks++
	p.Bytes += count
	if err = s.save(p); err != nil {
		_ = s.purge(p, "failed")
		fail(w, 500, "Storage unavailable")
		return
	}
	w.WriteHeader(204)
}

func (s *Server) consume(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	p := s.packages[id]
	if p == nil || p.Status != "ready" || !s.now().Before(p.ExpiresAt) || !matchesClaimToken(r.Header.Get("X-Claim-Token"), p.ClaimHash) {
		s.mu.Unlock()
		s.publicFailure(w, 404, "Package already viewed or does not exist")
		return
	}
	// Bounds audit growth from a leaked reusable link; 429 happens before any claim.
	if !s.allowedLocked("claim:"+id, maxClaimsPerPackagePerMinute) {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "Too many retrievals; no package has been claimed")
		return
	}
	openedAt := s.now()
	retrieval, err := s.sealRecord(id, auditRecord{OpenedAt: &openedAt, OpenedIP: s.peerIP(r), OpenedBrowser: browserProfile(r)})
	if err == nil {
		err = s.appendRetrieval(p, retrieval)
	}
	if err != nil {
		s.mu.Unlock()
		fail(w, 500, "Storage unavailable")
		return
	}
	if p.OneTime {
		p.Status = "consuming"
	}
	setLastRetrieval(p, retrieval)
	if err := s.save(p); err != nil {
		if p.OneTime {
			_ = s.purge(p, "failed")
		}
		s.mu.Unlock()
		fail(w, 500, "Storage unavailable")
		return
	}
	p.activeReads++
	oneTime, chunks, size := p.OneTime, p.Chunks, p.Bytes
	s.mu.Unlock()
	completed := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		p.activeReads--
		status := p.Status
		if oneTime {
			status = "failed"
			if completed {
				status = "consumed"
			}
		}
		if oneTime || (p.activeReads == 0 && status != "ready") {
			if err := s.purge(p, status); err != nil {
				log.Print("ERROR: ciphertext cleanup failed; sweep will retry")
			}
		}
	}()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="encrypted-package.bin"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size+int64(4*chunks), 10))
	controller := http.NewResponseController(w)
	for n := 0; n < chunks; n++ {
		if r.Context().Err() != nil {
			return
		}
		f, err := os.Open(s.chunk(id, n))
		if err != nil {
			return
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return
		}
		// One-time records are unlinked before sending, even for interrupted transfers.
		if oneTime {
			if err = os.Remove(s.chunk(id, n)); err != nil {
				f.Close()
				return
			}
		}
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(info.Size()))
		_ = controller.SetWriteDeadline(time.Now().Add(2 * time.Minute))
		if _, err = w.Write(header[:]); err == nil {
			_, err = io.Copy(w, f)
		}
		f.Close()
		if err != nil {
			return
		}
	}
	completed = true
}
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
func main() {
	config, err := listenerConfigFromEnv()
	if err != nil {
		log.Fatal("Invalid listener configuration: ", err)
	}
	if len(os.Args) > 1 {
		if len(os.Args) != 2 || os.Args[1] != "healthcheck" {
			log.Fatal("Unknown command")
		}
		if err := config.healthCheck(); err != nil {
			log.Fatal(err)
		}
		return
	}
	limits, err := gateLimitsFromEnv()
	if err != nil {
		log.Fatal("Invalid resource limits: ", err)
	}
	origin := env("PUBLIC_ORIGIN", "https://vault.miszori.dev")
	quota, err := strconv.ParseInt(env("MAX_STORAGE_BYTES", "107374182400"), 10, 64)
	if err != nil || quota < maxChunk {
		log.Fatal("Invalid MAX_STORAGE_BYTES")
	}
	s, err := newServer(env("DATA_DIR", "/data"), env("ADMIN_USER", "admin"), os.Getenv("ADMIN_SETUP_TOKEN"), origin, quota)
	if err != nil {
		log.Fatal("Cannot initialize storage: ", err)
	}
	s.gate = newRequestGate(limits)
	s.trustedProxy = config.trustedProxy
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.sweep(); err != nil {
					log.Print("ERROR: expiry cleanup failed")
				}
			}
		}
	}()
	log.Printf("Encrypted package service: public %s, VPN %s", config.publicAddr, config.adminAddr)
	if err := s.serveListeners(ctx, config); err != nil {
		log.Fatal(err)
	}
}
