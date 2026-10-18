package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

type EncryptedName struct {
	Version    int    `json:"version"`
	IV         string `json:"iv"`
	Ciphertext string `json:"ciphertext"`
}

type LabelKey struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

func canonicalBase64(s string, min, max int) bool {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) >= min && len(b) <= max && base64.RawURLEncoding.EncodeToString(b) == s
}

func (s *Server) initLabelKey() error {
	name := filepath.Join(s.root, "label-salt")
	b, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		for _, p := range s.packages {
			if p.EncryptedName != nil {
				return errors.New("label-salt missing while encrypted package names exist; restore the original salt")
			}
		}
		b = make([]byte, 16)
		if _, err = rand.Read(b); err != nil {
			return err
		}
		f, err := os.CreateTemp(s.root, ".label-salt-")
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
		// Link publishes a complete file without replacing a concurrently created salt.
		if err = os.Link(f.Name(), name); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err = os.Remove(f.Name()); err != nil {
			return err
		}
		d, err := os.Open(s.root)
		if err != nil {
			return err
		}
		err = d.Sync()
		closeErr = d.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		b, err = os.ReadFile(name)
	}
	if err != nil {
		return err
	}
	if len(b) != 16 {
		return fmt.Errorf("invalid label-salt length: %d", len(b))
	}
	if err = os.Chmod(name, 0600); err != nil {
		return err
	}
	s.labelKey = LabelKey{Version: 1, Salt: base64.RawURLEncoding.EncodeToString(b), Iterations: 600000}
	return nil
}

// patchName is called under the package lock, independently of upload state or token.
func (s *Server) patchName(w http.ResponseWriter, r *http.Request, p *Package) {
	var req struct {
		EncryptedName json.RawMessage `json:"encryptedName"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.EncryptedName) == 0 {
		fail(w, 400, "encryptedName is required")
		return
	}
	var name *EncryptedName
	d := json.NewDecoder(bytes.NewReader(req.EncryptedName))
	d.DisallowUnknownFields()
	if err := d.Decode(&name); err != nil || name != nil && (name.Version != 1 || !canonicalBase64(name.IV, 12, 12) || !canonicalBase64(name.Ciphertext, 17, 512)) {
		fail(w, 400, "Invalid encrypted name")
		return
	}
	updated := *p
	updated.EncryptedName = name
	if err := s.save(&updated); err != nil {
		fail(w, 500, "Storage unavailable")
		return
	}
	p.EncryptedName = name
	w.WriteHeader(http.StatusNoContent)
}
