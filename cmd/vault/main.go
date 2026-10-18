package main

import (
	"context"
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

type Package struct {
	ID             string          `json:"id"`
	OneTime        bool            `json:"oneTime"`
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
	activeReads    int
	auditBroken    bool
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
	now                func() time.Time
	labelKey           LabelKey
	gate               *requestGate
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
	return nil
}
func newServer(root, user, setupToken, origin string, quota int64) (*Server, error) {
	if user == "" {
		user = "admin"
	}
	s := &Server{root: root, user: user, origin: origin, quota: quota, packages: map[string]*Package{}, limits: map[string]bucket{}, now: time.Now, gate: newRequestGate(defaultGateLimits())}
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
		d := diskPackage{Package: Package{OneTime: true}}
		if err = json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		if d.ID != e.Name() {
			return nil, errors.New("invalid stored package ID")
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
		if (p.Status == "uploading" || p.Status == "ready") && !now.Before(p.ExpiresAt) {
			if err := s.purge(p, "expired"); err != nil {
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
func peerIP(r *http.Request) string {
	// Only the isolated Caddy network can supply this header. No backend port is published.
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	_, trusted, _ := net.ParseCIDR("172.30.0.0/24")
	if trusted.Contains(ip) {
		if real := net.ParseIP(r.Header.Get("X-Real-IP")); real != nil {
			return real.String()
		}
	}
	return host
}
func (s *Server) allowed(key string, n int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	b := s.limits[key]
	if now.Sub(b.start) >= time.Minute {
		b = bucket{start: now}
	}
	b.count++
	if len(s.limits) > 10000 {
		for k, v := range s.limits {
			if now.Sub(v.start) >= time.Minute {
				delete(s.limits, k)
			}
		}
		if len(s.limits) > 10000 {
			return false
		}
	}
	s.limits[key] = b
	return b.count <= n
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength != 0 {
		// Error responses must not leave an unread body draining on an unbounded keep-alive socket.
		r.Close = true
		w.Header().Set("Connection", "close")
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(time.Now().Add(2 * time.Minute))
		defer controller.SetReadDeadline(time.Time{})
	}
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
			if !s.allowed("discovery:"+peerIP(r), 20) || !s.gate.allowAdminDiscovery(s.now()) {
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
	if !s.allowed("public:"+peerIP(r), 120) || !s.gate.allowPublic(s.now()) {
		fail(w, 429, "Too many requests")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "packages" || !validID(parts[2]) {
		fail(w, 404, "Package already viewed or does not exist")
		return
	}
	id := parts[2]
	if len(parts) == 4 && parts[3] == "consume" && r.Method == "POST" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			r.Close = true
			w.Header().Set("Connection", "close")
			fail(w, 400, "Download claims must not contain a request body")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "Cross-origin request denied")
			return
		}
		s.consume(w, r, id)
		return
	}
	if len(parts) == 3 && r.Method == "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
		p := s.packages[id]
		if p == nil || p.Status != "ready" || !validClaimHash(p.ClaimHash) || !s.now().Before(p.ExpiresAt) {
			fail(w, 404, "Package already viewed or does not exist")
			return
		}
		writeJSON(w, 200, map[string]any{"status": "ready", "expiresAt": p.ExpiresAt, "oneTime": p.OneTime})
		return
	}
	fail(w, 404, "Not found")
}
func (s *Server) storageUsedLocked() int64 {
	var used int64
	for _, p := range s.packages {
		if p.Status == "ready" || p.Status == "uploading" || p.Status == "consuming" || p.activeReads > 0 {
			used += p.Bytes
		}
	}
	return used
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/")
	if path == "config" && r.Method == "GET" {
		writeJSON(w, 200, map[string]any{"publicOrigin": s.origin, "labelKey": s.labelKey})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
			TTL     int64 `json:"ttlSeconds"`
			OneTime *bool `json:"oneTime"`
		}
		if !decode(w, r, &req) {
			return
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
		p := &Package{ID: randomID(), OneTime: oneTime, Status: "uploading", CreatedAt: now, ExpiresAt: now.Add(time.Duration(req.TTL) * time.Second), TokenHash: hash(token)}
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
		writeJSON(w, 201, map[string]any{"id": p.ID, "uploadToken": token, "expiresAt": p.ExpiresAt, "oneTime": p.OneTime})
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
	if len(parts) == 4 && parts[2] == "chunks" && r.Method == "PUT" {
		n, err := strconv.Atoi(parts[3])
		if err != nil || n < 0 || n >= maxChunks {
			fail(w, 400, "Invalid chunk index")
			return
		}
		if n != p.Chunks {
			fail(w, 409, "Chunks must be uploaded in order; retries must reuse the next index")
			return
		}
		used := s.storageUsedLocked()
		f, err := os.OpenFile(s.chunk(p.ID, n)+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			fail(w, 500, "Storage unavailable")
			return
		}
		count, err := io.Copy(f, http.MaxBytesReader(w, r.Body, maxChunk))
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil || count < 16 || p.Bytes+count > maxPackageBytes || used+count > s.quota {
			_ = os.Remove(s.chunk(p.ID, n) + ".tmp")
			fail(w, 413, "Chunk, package, or storage limit exceeded")
			return
		}
		if err = os.Rename(s.chunk(p.ID, n)+".tmp", s.chunk(p.ID, n)); err != nil {
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
		if req.Chunks != p.Chunks || req.Chunks < 1 || !validClaimHash(req.ClaimHash) {
			fail(w, 400, "Incomplete package")
			return
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
func (s *Server) consume(w http.ResponseWriter, r *http.Request, id string) {
	s.mu.Lock()
	p := s.packages[id]
	if p == nil || p.Status != "ready" || !s.now().Before(p.ExpiresAt) || !matchesClaimToken(r.Header.Get("X-Claim-Token"), p.ClaimHash) {
		s.mu.Unlock()
		fail(w, 404, "Package already viewed or does not exist")
		return
	}
	retrieval := Retrieval{OpenedAt: s.now(), OpenedIP: peerIP(r), OpenedBrowser: browserProfile(r)}
	if err := s.appendRetrieval(p, retrieval); err != nil {
		s.mu.Unlock()
		fail(w, 500, "Storage unavailable")
		return
	}
	if p.OneTime {
		p.Status = "consuming"
	}
	p.OpenedAt = &retrieval.OpenedAt
	p.OpenedIP = retrieval.OpenedIP
	p.OpenedBrowser = retrieval.OpenedBrowser
	if err := s.save(p); err != nil {
		_ = s.purge(p, "failed")
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
				log.Print("ERROR: ciphertext cleanup failed; manual intervention required")
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
	if len(os.Args) > 1 {
		if len(os.Args) != 2 || os.Args[1] != "healthcheck" {
			log.Fatal("Unknown command")
		}
		if err := healthCheck("http://127.0.0.1:8080/healthz"); err != nil {
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
	server := &http.Server{Addr: ":8080", Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal(err)
	}
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
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	}()
	log.Print("Encrypted package service listening on :8080")
	if err = server.Serve(s.gate.limitListener(listener)); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-shutdownDone
}
