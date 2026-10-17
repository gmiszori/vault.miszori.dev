package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestValidClaimHash(t *testing.T) {
	for _, value := range []string{strings.Repeat("0", 64), strings.Repeat("abcdef0123456789", 4)} {
		if !validClaimHash(value) {
			t.Fatalf("valid hash rejected: %q", value)
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("é", 32), " " + strings.Repeat("a", 63), strings.Repeat("a", 63) + "\n"} {
		if validClaimHash(value) {
			t.Fatalf("invalid hash accepted: %q", value)
		}
	}
}

func TestMatchesClaimToken(t *testing.T) {
	raw := bytes.Repeat([]byte{255}, 32)
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	if !matchesClaimToken(token, hash) {
		t.Fatal("valid token rejected")
	}
	badTokens := []string{
		"", "wrong", token + "=", token + "==", token[:42], token + "A",
		" " + token, token + "\n", token[:20] + "\r\n" + token[20:],
		base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw),
		base64.RawURLEncoding.EncodeToString(raw[:31]), base64.RawURLEncoding.EncodeToString(append(raw, 0)),
		token[:42] + "9", // Same decoded bytes with nonzero unused padding bits.
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		hash, base64.RawURLEncoding.EncodeToString(digest[:]),
		strings.Repeat("é", 43), strings.Repeat("\x00", 43),
	}
	for _, bad := range badTokens {
		if matchesClaimToken(bad, hash) {
			t.Fatalf("invalid token accepted: %q", bad)
		}
	}
	for _, badHash := range []string{"", strings.Repeat("0", 64), strings.ToUpper(hash), hash[:63], hash + "0", strings.Repeat("z", 64), token} {
		if matchesClaimToken(token, badHash) {
			t.Fatalf("invalid or wrong hash accepted: %q", badHash)
		}
	}
}
